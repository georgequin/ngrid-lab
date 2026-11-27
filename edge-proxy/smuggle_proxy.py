#!/usr/bin/env python3
"""
nibbs-api-lab edge proxy — INTENTIONALLY VULNERABLE to HTTP request smuggling.

Why a custom proxy instead of nginx/haproxy?
--------------------------------------------
Modern nginx/HAProxy buffer and re-frame request bodies, which normalizes away
the Content-Length / Transfer-Encoding disagreement that smuggling relies on, so
they do NOT reliably reproduce a desync against an embedded-Tomcat backend in a
self-contained lab. This proxy reproduces the classic primitive deterministically
by deliberately framing requests the "old/naive" way:

  * It frames every request using **Content-Length only** and IGNORES
    Transfer-Encoding, then naively splices any trailing bytes straight through.
  * The Spring/Tomcat backend honors Transfer-Encoding: chunked (verified), so a
    request pipelined after a "0\\r\\n\\r\\n" chunk is executed by the backend but
    never seen by the WAF below -> CL.TE-style request smuggling.
  * A trivial "WAF" blocks request LINES that touch /internal and the
    X-Internal-Caller header, so the exercise is a chunked-encoding WAF bypass.
  * Upstream connections are pooled LIFO: concurrent requests get distinct
    connections (so the backend's TOCTOU race is reachable through the proxy),
    while a just-used connection is handed to the very next request (so a
    smuggled, queued response deterministically poisons that next victim).

Do not use any of this outside the lab.
"""
import os
import socket
import threading

LISTEN_HOST = os.environ.get("PROXY_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PROXY_LISTEN_PORT", "8088"))
UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "gateway-app")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "8080"))
POOL_SIZE = int(os.environ.get("UPSTREAM_POOL", "16"))

# Planted WAF: refuses request lines that reference the internal surface, and
# the X-Internal-Caller marker. Only the REQUEST LINE + HEADERS are inspected,
# never the body — which is what the smuggle slips past.
WAF_BLOCK_PATH_TOKENS = (b"/internal",)
WAF_BLOCK_HEADER_TOKENS = (b"x-internal-caller",)

# ----- LIFO upstream connection pool (each conn carries its own read buffer) --
_free = []                       # stack of {"sock","buf"} dicts
_cv = threading.Condition()
_created = 0


def _checkout():
    global _created
    with _cv:
        while True:
            if _free:
                return _free.pop()          # LIFO: most-recently-returned first
            if _created < POOL_SIZE:
                _created += 1
                return {"sock": None, "buf": b""}
            _cv.wait()


def _checkin(conn):
    with _cv:
        _free.append(conn)
        _cv.notify()


def _ensure_sock(conn):
    if conn["sock"] is None:
        s = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn["sock"] = s
        conn["buf"] = b""
    return conn["sock"]


def _reset(conn):
    if conn["sock"] is not None:
        try:
            conn["sock"].close()
        except OSError:
            pass
    conn["sock"] = None
    conn["buf"] = b""


def _content_length(header_block):
    for line in header_block.split(b"\r\n"):
        name, sep, value = line.partition(b":")
        if sep and name.strip().lower() == b"content-length":
            try:
                return int(value.strip())
            except ValueError:
                return 0
    return 0


def _client_read_headers(sock, pre=b""):
    buf = pre
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head + b"\r\n\r\n", rest


def _up_read_headers(conn):
    sock = conn["sock"]
    while b"\r\n\r\n" not in conn["buf"]:
        chunk = sock.recv(4096)
        if not chunk:
            break
        conn["buf"] += chunk
    head, _, rest = conn["buf"].partition(b"\r\n\r\n")
    conn["buf"] = rest
    return head + b"\r\n\r\n"


def _up_consume_chunked(conn):
    sock = conn["sock"]
    raw = b""
    while True:
        while b"\r\n" not in conn["buf"]:
            c = sock.recv(4096)
            if not c:
                return raw + conn["buf"]
            conn["buf"] += c
        idx = conn["buf"].index(b"\r\n")
        try:
            size = int(conn["buf"][:idx].split(b";")[0].strip(), 16)
        except ValueError:
            raw += conn["buf"]
            conn["buf"] = b""
            return raw
        needed = idx + 2 + size + 2
        while len(conn["buf"]) < needed:
            c = sock.recv(4096)
            if not c:
                break
            conn["buf"] += c
        raw += conn["buf"][:needed]
        conn["buf"] = conn["buf"][needed:]
        if size == 0:
            return raw


def _up_read_one_response(conn):
    """Read exactly one response (chunked or CL); keep any over-read bytes in the
    connection buffer so a queued/smuggled response poisons the next user."""
    head = _up_read_headers(conn)
    if b"transfer-encoding: chunked" in head.lower():
        return head + _up_consume_chunked(conn)
    clen = _content_length(head)
    while len(conn["buf"]) < clen:
        chunk = conn["sock"].recv(4096)
        if not chunk:
            break
        conn["buf"] += chunk
    body = conn["buf"][:clen]
    conn["buf"] = conn["buf"][clen:]
    return head + body


def _force_client_close(response):
    """This proxy serves ONE request per client connection then closes it.
    Advertise that with `Connection: close` on the client-facing response so
    keep-alive clients (browsers, Burp) open a fresh connection per request
    instead of reusing the just-closed socket and getting "no response from
    remote server". Only the response HEAD sent to the client is rewritten;
    upstream framing, the body, the LIFO pool and the smuggling desync are all
    left exactly as they were."""
    head, sep, body = response.partition(b"\r\n\r\n")
    if not sep:
        return response
    lines = head.split(b"\r\n")
    kept = [lines[0]]  # status line
    for ln in lines[1:]:
        name = ln.split(b":", 1)[0].strip().lower()
        if name in (b"connection", b"keep-alive", b"proxy-connection"):
            continue
        kept.append(ln)
    kept.append(b"Connection: close")
    return b"\r\n".join(kept) + b"\r\n\r\n" + body


def handle_client(client, addr):
    try:
        head, leftover = _client_read_headers(client)
        if not head.strip():
            client.close()
            return
        request_line = head.split(b"\r\n", 1)[0]
        clen = _content_length(head)                   # TE ignored (the bug)
        body = leftover
        while len(body) < clen:
            chunk = client.recv(4096)
            if not chunk:
                break
            body += chunk
        consumed, trailing = body[:clen], body[clen:]

        # Naive splice: also relay bytes already buffered beyond the counted body.
        # For a chunked request the proxy counts 0 body bytes, so the whole
        # payload + any pipelined request rides through here, unseen by the WAF.
        client.setblocking(False)
        try:
            while True:
                extra = client.recv(4096)
                if not extra:
                    break
                trailing += extra
        except (BlockingIOError, OSError):
            pass
        finally:
            client.setblocking(True)
        raw_request = head + consumed + trailing

        # "WAF": inspect only the request line + headers (never the body).
        low_line = request_line.lower()
        low_head = head.lower()
        if any(t in low_line for t in WAF_BLOCK_PATH_TOKENS) \
                or any(t in low_head for t in WAF_BLOCK_HEADER_TOKENS):
            resp = b"WAF blocked (edge)"
            client.sendall(
                b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
                b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(resp), resp))
            client.close()
            return

        conn = _checkout()
        try:
            try:
                _ensure_sock(conn).sendall(raw_request)
                response = _up_read_one_response(conn)
            except (BrokenPipeError, ConnectionResetError, OSError):
                _reset(conn)
                _ensure_sock(conn).sendall(raw_request)
                response = _up_read_one_response(conn)
            client.sendall(_force_client_close(response))
        finally:
            _checkin(conn)
    except Exception as e:  # noqa
        try:
            msg = ("proxy error: %s" % e).encode()
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\n"
                           b"Connection: close\r\n\r\n%s" % (len(msg), msg))
        except OSError:
            pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(256)
    print("edge-proxy (vulnerable) listening on %s:%d -> %s:%d (pool=%d)"
          % (LISTEN_HOST, LISTEN_PORT, UPSTREAM_HOST, UPSTREAM_PORT, POOL_SIZE),
          flush=True)
    while True:
        client, addr = srv.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    main()

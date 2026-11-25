# Intentionally vulnerable edge proxy (HTTP request smuggling / chunked WAF bypass).
# A small purpose-built proxy is used instead of nginx/HAProxy because modern
# nginx/HAProxy re-frame request bodies and normalize away the desync, so they
# do not reliably reproduce smuggling against the hardened embedded-Tomcat
# backend in a self-contained lab. See smuggle_proxy.py for the planted bugs.
FROM python:3.12-alpine

WORKDIR /app
COPY smuggle_proxy.py /app/smuggle_proxy.py

ENV PROXY_LISTEN_HOST=0.0.0.0 \
    PROXY_LISTEN_PORT=8088 \
    UPSTREAM_HOST=gateway-app \
    UPSTREAM_PORT=8080

EXPOSE 8088
CMD ["python3", "/app/smuggle_proxy.py"]

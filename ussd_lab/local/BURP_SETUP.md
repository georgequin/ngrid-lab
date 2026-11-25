# Pointing Burp Suite Community at the range

The handset page and the gateway are plain HTTP on loopback, so Burp sees everything the handset sends. Use your participant URL: `http://127.0.0.1:800N` (local participant 1 is `8001`).

## Setup (5 minutes)
1. Start Burp Suite Community, choose **Temporary project**, then **Use Burp defaults**.
2. **Proxy > Proxy settings**: confirm a listener on `127.0.0.1:8080` (the default). Leave it running.
3. **Proxy > Intercept**: turn **Intercept on**.
4. Click **Open browser** (Burp's embedded Chromium; it is already proxied and handles loopback addresses).
5. In that browser open `http://127.0.0.1:8001` and press **Dial *384#**.
6. In Burp you should see a held request `POST /gw/ussd` with a JSON body such as `{"input":"","sessionId":""}`. Press **Forward**, then turn Intercept off. Requests now appear in **Proxy > HTTP history**.

## Using your own browser instead (Firefox)
Set the manual proxy to `127.0.0.1` port `8080`. Firefox does not proxy loopback by default: open `about:config`, set `network.proxy.allow_hijacking_localhost` to `true`, and make sure the *No proxy for* box does not contain `127.0.0.1` or `localhost`. Chrome and Edge also bypass the proxy for loopback unless you add `<-loopback>` to the proxy bypass list.

## The core exercise loop (scenario 1)
1. In **HTTP history** right-click a `POST /gw/ussd` request and choose **Send to Repeater**.
2. In Repeater add one header line: `X-MSISDN: 2348000000001`.
3. Send with `{"input":"1","sessionId":"<value from the earlier response>"}`. Read the response `screen`.
4. Record the request, the response and any `EVID-S...` token on your evidence sheet.
Switch your range to the secured profile and repeat step 2 and 3: the header is ignored.

## Scenario hints
* **Sessions (3, 4):** the session id is in the JSON `sessionId` field of requests and responses. Change it in Repeater. You can also add a numeric `"exp"` field to the JSON body.
* **PIN (5):** use Repeater, not Intruder. Burp Community throttles Intruder and the range enforces a budget of 25 attempts per account.
* **SMPP / MO-SMS (10):** in Repeater create a `POST /smpp/mo` request with a JSON body. Content type `application/json`.
* **Wire and logs (8):** open `/lab/wire` and `/lab/logs` in the Burp browser; they are ordinary GET requests.

## Troubleshooting
| Symptom | Fix |
|---|---|
| Nothing in HTTP history | Your browser is bypassing the proxy for loopback (see Firefox note), or you are using a browser other than Burp's |
| Page loads but request never completes | Intercept is on and a request is waiting: press Forward |
| Browser will not open on Linux | Run Burp as a normal user from a terminal; the embedded browser needs a sandbox-capable environment |

## What was verified here
The automated suite sends the same requests through a stand-in HTTP proxy on port 8080 that rewrites headers (tests in `tests/test_4_burp_proxy.py`). That proves the handset page and `/gw/ussd` work through a proxy and that header tampering behaves as described. It has **not** been run with Burp Suite itself, so confirm steps 1 to 6 once on your own machine.

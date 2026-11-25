#!/bin/sh
set -e
mkdir -p /data /certs
[ -f /certs/ca.crt ] || sh /app/gen_certs.sh
[ -f /data/mode ] || echo vulnerable > /data/mode
python gen_signalling.py
python backend.py &
exec python app.py

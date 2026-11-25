#!/usr/bin/env python3
"""Local docker-compose generator (no /opt/lab, no root). One isolated container per participant.
Usage: gen_compose_local.py <env_name> <count> <base_port> <lab_secret> <admin_token> > docker-compose.yml
Containers publish only on 127.0.0.1. Timers can be shortened for tests via IDLE/ABS/SWAP_WINDOW env at 'up' time."""
import sys
name, n, base, secret, admin = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
print(f"name: ussd-{name}\nservices:")
for i in range(1, n + 1):
    print(f"""  p{i}:
    build: ./range
    image: ussd-range-{name}:local
    restart: unless-stopped
    mem_limit: 256m
    ports: ["127.0.0.1:{base + i}:8080"]
    environment:
      LAB_ID: {name}-p{i}
      LAB_SECRET: "{secret}-p{i}"
      ADMIN_TOKEN: "{admin}"
      IDLE: "${{IDLE:-90}}"
      ABS: "${{ABS:-600}}"
      SWAP_WINDOW: "${{SWAP_WINDOW:-900}}"
    volumes: ["./data/p{i}:/data"]""")

#!/usr/bin/env python3
"""Generate docker-compose.yml: one isolated range container per participant, bound to 127.0.0.1 only.
Usage: gen_compose.py <team_id> <participants> <lab_secret> <admin_token> > docker-compose.yml"""
import sys
team, n, secret, admin = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
print("services:")
for i in range(1, n + 1):
    print(f"""  p{i}:
    image: ussd-range:latest
    restart: unless-stopped
    mem_limit: 256m
    ports: ["127.0.0.1:{8000+i}:8080"]
    environment:
      LAB_ID: team{team}-p{i}
      LAB_SECRET: "{secret}-p{i}"
      ADMIN_TOKEN: "{admin}"
    volumes: ["/opt/lab/data/p{i}:/data"]""")

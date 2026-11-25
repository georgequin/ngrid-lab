#!/bin/bash
# Instructor control on a team host (run with sudo). /opt/lab/.env is root-only, so participants cannot run this.
# Usage: labctl.sh status | mode <vulnerable|secure> [N] | reset [N] | logs N
source /opt/lab/.env
N_ALL=$(seq 1 "${PARTICIPANTS:-10}")
each() { for i in ${2:-$N_ALL}; do curl -s -X POST -H "X-Admin-Token: $ADMIN_TOKEN" -H 'Content-Type: application/json' ${3:+-d "$3"} "localhost:$((8000+i))$1" >/dev/null && echo "p$i ok"; done; }
case "$1" in
  status) for i in $N_ALL; do echo -n "p$i: "; curl -s "localhost:$((8000+i))/lab/status" | python3 -c 'import sys,json;j=json.load(sys.stdin);print(j["profile"],j["pin_attempts_used"])'; done;;
  mode)   each /admin/mode "$3" "{\"mode\":\"$2\"}";;
  reset)  each /admin/reset "$2";;
  logs)   curl -s "localhost:$((8000+$2))/lab/logs";;
  *) echo "usage: $0 status | mode <vulnerable|secure> [N] | reset [N] | logs N";;
esac

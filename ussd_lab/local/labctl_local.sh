#!/bin/bash
# Local instructor control, no root needed.
# Usage: local/labctl_local.sh <instructor|participant> <up|down|status|mode|reset|logs|sigkey> [args]
#   up | down | status
#   mode <vulnerable|secure> [N]      reset [N]      logs N      sigkey N (instructor env only)
cd "$(dirname "$0")/.."; E=$1; CMD=$2; shift 2 2>/dev/null
D=local/run/$E; [ -f $D/.env ] || { echo "run local/setup.sh first"; exit 1; }
set -a; source $D/.env; set +a
[ "$TIMERS" = short ] && export IDLE=3 ABS=8 SWAP_WINDOW=5
ALL=$(seq 1 "$COUNT")
call() { curl -s -X POST -H "X-Admin-Token: $ADMIN_TOKEN" -H 'Content-Type: application/json' ${3:+-d "$3"} "127.0.0.1:$((BASE_PORT+$2))$1" >/dev/null && echo "p$2 ok" || echo "p$2 FAILED"; }
case "$CMD" in
  up)     docker compose -f $D/docker-compose.yml --project-directory $D up -d --build;;
  down)   docker compose -f $D/docker-compose.yml --project-directory $D down;;
  status) for i in $ALL; do echo -n "p$i: "; o=$(curl -sf --max-time 3 "127.0.0.1:$((BASE_PORT+i))/lab/status") && echo "$o" | python3 -c 'import sys,json;j=json.load(sys.stdin);print(j["profile"],j["pin_attempts_used"])' || echo DOWN; done;;
  mode)   for i in ${2:-$ALL}; do call /admin/mode $i "{\"mode\":\"$1\"}"; done;;
  reset)  for i in ${1:-$ALL}; do call /admin/reset $i; done;;
  logs)   curl -s "127.0.0.1:$((BASE_PORT+$1))/lab/logs";;
  sigkey) [ "$E" = instructor ] && { cat $D/data/p$1/.sig_key.json; echo; } || echo "instructor env only";;
  *) sed -n '2,6p' "$0";;
esac

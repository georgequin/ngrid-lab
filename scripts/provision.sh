#!/usr/bin/env bash
# Provision / tear down many ISOLATED nibbs-api-lab seats for a classroom range.
#
# Usage:
#   scripts/provision.sh up   [COUNT] [BASE_PORT]   # default COUNT=5  BASE_PORT=9000
#   scripts/provision.sh down  [COUNT] [BASE_PORT]
#   scripts/provision.sh list
#
# Seat i (1..COUNT) is compose project "nibbs-seat-i", with its edge proxy
# published on 127.0.0.1:(BASE_PORT+i). db and gateway stay internal to each
# seat's private network, so 200 seats never collide on host ports.
#
# For a full 200-seat range:  scripts/provision.sh up 200 9000
# (That publishes 127.0.0.1:9001 .. 127.0.0.1:9200.)
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE_FILE=docker-compose.seat.yml
ACTION="${1:-up}"
COUNT="${2:-5}"
BASE_PORT="${3:-9000}"
PREFIX=nibbs-seat

build_images() {
  echo ">> Building shared images once (gateway + edge)..."
  EDGE_PORT=1 docker compose -f "$COMPOSE_FILE" -p ${PREFIX}-build build
  # Remove the throwaway build project's (unstarted) resources, keep the images.
  docker compose -f "$COMPOSE_FILE" -p ${PREFIX}-build down >/dev/null 2>&1 || true
}

case "$ACTION" in
  up)
    build_images
    echo ">> Launching $COUNT seats (edge ports $((BASE_PORT+1))..$((BASE_PORT+COUNT)))"
    for i in $(seq 1 "$COUNT"); do
      port=$((BASE_PORT + i))
      EDGE_PORT="$port" docker compose -f "$COMPOSE_FILE" -p "${PREFIX}-${i}" up -d >/dev/null
      printf "   seat %-4s -> http://127.0.0.1:%s\n" "$i" "$port"
    done
    echo ">> Done. Reset a seat's ledger with:  curl -X POST http://127.0.0.1:PORT/reset"
    ;;
  down)
    echo ">> Tearing down $COUNT seats..."
    for i in $(seq 1 "$COUNT"); do
      docker compose -f "$COMPOSE_FILE" -p "${PREFIX}-${i}" down -v >/dev/null 2>&1 || true
      echo "   seat $i down"
    done
    ;;
  list)
    docker compose ls 2>/dev/null | grep "$PREFIX" || echo "no $PREFIX projects running"
    ;;
  *)
    echo "usage: $0 {up|down|list} [COUNT] [BASE_PORT]" >&2
    exit 2
    ;;
esac

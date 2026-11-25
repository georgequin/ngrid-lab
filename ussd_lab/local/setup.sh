#!/bin/bash
# Build both local environments from the real bundles. Safe to re-run: only touches local/run/.
# Usage: local/setup.sh            (normal timers)
#        TEST_TIMERS=1 local/setup.sh   (idle 3s, absolute 8s, SIM window 5s; for the pytest suite)
set -e; cd "$(dirname "$0")/.."; R=local/run
./scripts/package.sh >/dev/null
mkdir -p $R/instructor $R/participant
for E in instructor participant; do
  B=$E; [ $E = participant ] && B=student                                  # participant env is built from the STUDENT bundle only
  rm -rf $R/$E/range $R/$E/docs $R/$E/scripts                              # only our own run dir
  tar xzf dist/$B.tar.gz -C $R/$E
done
[ -f $R/instructor/.env ] || { echo "ADMIN_TOKEN=$(openssl rand -hex 12)"; echo "LAB_SECRET=$(openssl rand -hex 12)"; echo COUNT=3; echo BASE_PORT=8100; } > $R/instructor/.env
[ -f $R/participant/.env ] || { echo "ADMIN_TOKEN=$(openssl rand -hex 12)"; echo "LAB_SECRET=$(openssl rand -hex 12)"; echo COUNT=10; echo BASE_PORT=8000; } > $R/participant/.env
sed -i '/^TIMERS=/d' $R/*/.env
[ -n "$TEST_TIMERS" ] && for E in instructor participant; do echo "TIMERS=short" >> $R/$E/.env; done
for E in instructor participant; do
  set -a; source $R/$E/.env; set +a
  python3 local/gen_compose_local.py $E $COUNT $BASE_PORT "$LAB_SECRET" "$ADMIN_TOKEN" > $R/$E/docker-compose.yml
  mkdir -p $R/$E/data; chmod 600 $R/$E/.env
done
echo "ready: $R/instructor (8101-8103)  $R/participant (8001-8010)"

# Running the range locally (two separate environments)

| Environment | Containers | Ports (127.0.0.1 only) | Built from | Docs present |
|---|---|---|---|---|
| instructor | 3 | 8101 to 8103 | `dist/instructor.tar.gz` | yes (guide, answer key) |
| participant | 10 | 8001 to 8010 | `dist/student.tar.gz` only | handout only |

Each environment has its own compose project (`ussd-instructor`, `ussd-participant`), admin token, lab secret and per-container data volume. Needs Docker with the compose plugin, `bash`, `curl`, `openssl`, `python3`.

## First time
```bash
./local/setup.sh                 # normal timers (idle 90 s, absolute 600 s, SIM window 900 s)
TEST_TIMERS=1 ./local/setup.sh   # short timers (3 s / 8 s / 5 s) for the pytest suite
```
`setup.sh` rebuilds only `local/run/`. It never touches `/opt`, Terraform or the AWS bundles.

## Start, stop, status
```bash
./local/labctl_local.sh instructor  up       # build image and start 3 containers
./local/labctl_local.sh participant up       # build image and start 10 containers
./local/labctl_local.sh instructor  status   # profile + PIN attempts per container (DOWN if unreachable)
./local/labctl_local.sh participant down     # stop and remove containers (data stays in local/run/*/data)
```
Open `http://127.0.0.1:8001` (participant 1) or `http://127.0.0.1:8101` (instructor 1).

## Switch profile and reset
```bash
./local/labctl_local.sh participant mode secure           # all 10 containers
./local/labctl_local.sh participant mode vulnerable 4     # container p4 only
./local/labctl_local.sh participant reset                 # re-seed all (clears PIN budgets, logs, SIM events)
./local/labctl_local.sh participant reset 4               # p4 only
./local/labctl_local.sh instructor  sigkey 1              # signalling answer key for p1 (instructor env only)
./local/labctl_local.sh instructor  logs 1                # last 80 log lines for p1
```
Use `instructor` instead of `participant` for the instructor environment in every command.

## Run the tests
```bash
python -m pip install pytest requests
python -m pytest                                   # default: process harness, needs no Docker, ~45 s

TEST_TIMERS=1 ./local/setup.sh                     # against the real compose stacks instead
./local/labctl_local.sh instructor up && ./local/labctl_local.sh participant up
LAB_MODE=external python -m pytest
```
In `external` mode two tests that need container-internal ports (plain hop refused, mTLS enforced) are skipped. The remaining tests run unchanged.

## Notes
* Local participant environment keeps `.env` (admin token) and the range source on disk, readable by anyone on this machine. That is fine for testing. For a real class use the AWS deployment, where `/opt/lab` is root-only.
* `docker-compose.yml` files are generated; edit `gen_compose_local.py`, not the output.

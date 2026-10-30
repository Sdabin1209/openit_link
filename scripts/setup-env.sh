#!/usr/bin/env bash
# 영역 환경 준비(계약 SetupEnvReport): 진행 기록은 표준 오류, 표준 출력 마지막 줄은 SetupEnvReport JSON 한 줄.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
start=$(date +%s)
report() {
  local env=""
  [ "$1" = ok ] && env=',"environment":{"kind":"python-venv","path":".venv","test_command":[".venv/bin/python","-m","pytest","-q"]}'
  printf '{"area":"link","status":"%s","exit_code":%d,"seconds":%d%s}\n' "$1" "$2" "$(( $(date +%s) - start ))" "$env"
}
{ [ -d .venv ] || python3 -m venv .venv; } >&2 || { report fail 20; exit 20; }
.venv/bin/pip install -q -e . pytest waitress==3.0.2 >&2 || { report fail 20; exit 20; }
report ok 0

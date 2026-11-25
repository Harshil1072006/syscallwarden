#!/bin/sh
set -eu
case "${1:-}" in demo|live) mode=$1 ;; *) exit 2 ;; esac
mkdir -p out
output=$(mktemp -d "out/${mode}-XXXXXXXX")
project="sw-$(basename "$output" | tr '[:upper:]' '[:lower:]')-$$"
compose() {
    if [ "$mode" = live ]; then
        docker compose -p "$project" -f docker-compose.yml -f compose.live.yml "$@"
    else
        docker compose -p "$project" -f docker-compose.yml "$@"
    fi
}
cleanup() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
compose build
compose up -d lab
# A named, stopped sensor lets us export reports without a host bind mount.
sensor="$project-sensor-run"
trap 'docker rm -f "$sensor" >/dev/null 2>&1 || true; cleanup' EXIT
if ! compose run -T --no-deps --name "$sensor" sensor; then
    compose logs lab >&2 || true
    exit 1
fi
docker cp -L "$sensor:/report/latest/." "$output/"
echo "Reports: $output"

#!/usr/bin/env bash
# Stop + remove the local TVM sandbox.
NAME="${TVM_CONTAINER:-tvm-quickstart}"
docker rm -f "$NAME" >/dev/null 2>&1 && echo "removed $NAME" || echo "$NAME not running"

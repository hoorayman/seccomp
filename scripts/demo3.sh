#!/bin/sh
# Demo 03 的编排：先把 supervisor 放到后台（它自己不受过滤器约束），
# 再让 launcher 装过滤器 + 交接 fd + execve payload。
set -e

./bin/supervisor &
SUP=$!
sleep 0.5

./bin/launcher ./bin/payload || true

kill "$SUP" 2>/dev/null || true
wait "$SUP" 2>/dev/null || true

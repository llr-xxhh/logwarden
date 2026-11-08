#!/bin/sh
# 重新渲染架构图为 PNG（2 倍图）。改完 architecture.svg 后执行本脚本。
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
CHROME="/c/Program Files/Google/Chrome/Application/chrome.exe"

"$CHROME" --headless=new --disable-gpu --hide-scrollbars \
  --force-device-scale-factor=2 --window-size=680,748 \
  --screenshot="$DIR/architecture.png" \
  "file:///$(echo "$DIR" | sed 's|^/c/|C:/|')/architecture.svg"

echo "已更新 $DIR/architecture.png"

#!/bin/bash
# O6 (架构优化): 周期清理过期 prekey, 由 systemd timer 调用
# token 从受 600 权限保护的文件中读取, 不出现在进程参数里
# R4 修复: 端口 5002 与实际监听 5000 不符导致 timer 每日静默失败;
# 补 set -euo pipefail / 重试 / syslog 日志。端口可用环境变量覆盖。
set -euo pipefail

ZHPREKEY_PORT="${ZHPREKEY_PORT:-5000}"
TOKEN_FILE="${ZHPREKEY_ADMIN_TOKEN_FILE:-/opt/zhprekey/.admin_token}"
URL="http://127.0.0.1:${ZHPREKEY_PORT}/v1/admin/cleanup_expired"

if [[ ! -f "$TOKEN_FILE" ]]; then
  logger -t zhprekey-cleanup "错误: token 文件不存在: $TOKEN_FILE"
  exit 1
fi

resp=""
for i in 1 2 3; do
  if resp=$(curl -sS -f --max-time 30 -X POST \
      -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
      "$URL" 2>&1); then
    logger -t zhprekey-cleanup "成功: $resp"
    exit 0
  fi
  sleep $((i * 5))
done

logger -t zhprekey-cleanup "失败(重试3次): $resp"
exit 1

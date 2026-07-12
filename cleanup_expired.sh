#!/bin/bash
# O6 (架构优化): 周期清理过期 prekey, 由 systemd timer 调用
# token 从受 600 权限保护的文件中读取, 不出现在进程参数里
curl -s -X POST \
  -H "Authorization: Bearer $(cat /opt/zhprekey/.admin_token 2>/dev/null)" \
  http://127.0.0.1:5002/v1/admin/cleanup_expired

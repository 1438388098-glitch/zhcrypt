# zhcrypt 常用任务示例

> 全部命令可用 `zhcrypt --help` 查看参数; Windows 下把 `zhcrypt` 换成 `zhcrypt.exe`。

## 身份管理

```bash
zhcrypt init alice                      # 创建身份 (交互输入口令)
zhcrypt list                            # 列出本地身份
zhcrypt info                            # 算法栈与密钥存储信息
zhcrypt delete alice                    # 删除身份 (需输入名字确认, -y 跳过)
```

## 文本与文件加密

```bash
zhcrypt encrypt "秘密消息"               # 口令模式加密, 输出 Base64
zhcrypt encrypt "秘密消息" --temp-share  # 一次性临时口令 (6 词 ≈ 48bit)
zhcrypt decrypt "<粘贴密文>"             # 自动识别格式解密
zhcrypt encrypt-file 报告.docx           # 输出 报告.docx.zhe (流式分块)
zhcrypt decrypt-file 报告.docx.zhe       # 解密 (默认还原原名)
zhcrypt strength --stdin < pw.txt        # 口令强度检测 (不进 shell 历史)
```

## 备份与恢复

```bash
zhcrypt backup alice                     # 生成 .backup 文件 + 5 个 Shamir 份额
zhcrypt restore alice                    # 输入任意 3 个份额 + 新口令恢复私钥
```

## 端到端加密聊天

```bash
zhcrypt set-server https://你的域名 --token <tok> --pin <证书指纹>
zhcrypt cert-pin https://你的域名        # 计算并固定服务器证书指纹
zhcrypt chat                             # 启动 TUI 聊天 (斜杠命令 /help)
zhcrypt chat-send -t bob "你好"          # REST 单发
zhcrypt chat-history -t bob -n 20        # 查看历史
zhcrypt chat-safety -t bob               # 查看安全识别码 (务必线下比对)
zhcrypt chat-delete -t bob               # 删除会话 (重新握手)
```

## 自托管服务端

```bash
export ZHPREKEY_TOKEN=$(python -c 'import secrets; print(secrets.token_hex(16))')
export ZHPREKEY_DB=/opt/zhcrypt/zhprekey.db
python server.py                         # REST:5000 (明文, 建议前置 Nginx)

# 原生 TLS (小规模):
export ZHPREKEY_TLS_CERT=/path/cert.pem
export ZHPREKEY_TLS_KEY=/path/key.pem
python server.py

# 直连暴露 (无反代) 务必:
export ZHPREKEY_TRUST_PROXY=0

python chat_server.py                    # WebSocket:5003
```

## 验证与测试

```bash
python tests/run_core_tests.py           # 三套核心回归 (38+25+66)
python -m pytest tests/ -q               # 单元/端点/协议边界 (300+)
python tests/e2e_local_smoke.py          # 本地双端互通实测 (13 检查)
pip-audit -r requirements-client.lock.txt
```

"""
文件传输客户端层 (Agent-B)
==========================
职责: 与服务端 /v1/files/* 文件端点交互 —— 分块上传 (断点续传协商)、
Range 下载 (断点续传)、HEAD 元信息查询。

调用方负责加解密: 本类只搬运密文字节, 不做任何加密。
内部所有 HTTP 请求统一走 _http_raw(...) (urllib), 测试通过 monkeypatch 它做 mock。

用法:
    fc = FileClient(server_url, auth_token)
    result = fc.upload("cipher.bin", "peer_id")       # {"token": ...} 或 {"error": ...}
    result = fc.download(token, "downloads")          # {"path", "size"} 或 {"error": ...}
    info = fc.head(token)                             # {"size": int} 或 {"error": ...}
"""

import os
import re
import json
import time
import secrets
import urllib.parse

# 文件名/路径白名单 (AGENTS.md §1.5: 防穿越)
_TOKEN_RE = re.compile(r"^[\w.\-]+$")
# 分块大小: 1MB
CHUNK_SIZE = 1024 * 1024
# progress_cb 节流间隔: 每秒最多回调 1 次
PROGRESS_INTERVAL = 1.0


class FileClientError(Exception):
    """网络/传输层错误 (非业务错误), 由上层决定是否转为 {"error": ...}。"""


def _read_json_body(body: bytes):
    """安全解析 JSON 响应体; 失败返回空 dict。"""
    if not body:
        return {}
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return {}


class FileClient:
    def __init__(self, server_url: str, auth_token: str, identity: str = ""):
        self.server_url = (server_url or "").rstrip("/")
        self.auth_token = auth_token
        self.identity = identity
        self._last_progress = 0.0

    # ------------------------------------------------------------------
    # HTTP 底层 (测试 monkeypatch 本方法做 mock)
    # ------------------------------------------------------------------
    def _http_raw(self, method, url, headers=None, body=None, timeout=60):
        """原始 HTTP 请求 (urllib), 返回 (status: int, headers: dict, body: bytes)。

        网络层异常抛 FileClientError; HTTP 非 2xx 不抛, 由调用方按状态码处理。
        """
        import urllib.request
        import ssl

        req_headers = dict(headers or {})
        if not req_headers.get("Authorization"):
            req_headers["Authorization"] = f"Bearer {self.auth_token}"
        # Cloudflare 按 UA 拦截: 必须带应用 UA (同 chat_client._http_request)
        if not req_headers.get("User-Agent"):
            req_headers["User-Agent"] = "zhcrypt-client/3.1"

        req = urllib.request.Request(
            url, data=body, method=method, headers=req_headers)
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            try:
                ebody = e.read()
            except Exception:
                ebody = b""
            return e.code, dict(e.headers), ebody
        except Exception as e:
            raise FileClientError(str(e))

    def _auth_headers(self, extra=None):
        h = {"Authorization": f"Bearer {self.auth_token}"}
        if self.identity:
            h["X-Identity"] = self.identity
        if extra:
            h.update(extra)
        return h

    def _maybe_progress(self, progress_cb, done, total):
        """进度回调节流: 每秒最多回调 1 次; 完成时 (done>=total) 必回调。"""
        if not progress_cb:
            return
        now = time.time()
        if done >= total or now - self._last_progress >= PROGRESS_INTERVAL:
            self._last_progress = now
            try:
                progress_cb(done, total)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 上传
    # ------------------------------------------------------------------
    def upload(self, file_path: str, recipient: str, progress_cb=None,
               upload_token: str = None):
        """分块上传密文文件 (1MB/块), 支持断点续传协商。

        流程: 从 0 起逐块 POST {server}/v1/files/upload, 每块头
        X-Upload-Token (本次上传会话标识)/X-Recipient/X-Offset/X-Total-Size;
        若服务端返回 409 {"offset": n} 表示已有部分数据, 跳过已上传部分,
        从协商值 n 继续。
        upload_token: 可选; 传入后复用该会话 (跨调用断点续传),
        否则每次自动生成新会话。
        成功: {"token": str}   失败: {"error": 中文原因}
        """
        if not os.path.isfile(file_path):
            return {"error": f"文件不存在: {file_path}"}
        total = os.path.getsize(file_path)
        if total <= 0:
            return {"error": "空文件无法上传"}
        upload_token = upload_token or secrets.token_hex(16)
        url = f"{self.server_url}/v1/files/upload"
        self._last_progress = 0.0

        try:
            with open(file_path, "rb") as f:
                offset = 0
                while True:
                    f.seek(offset)
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    status, _headers, body = self._http_raw(
                        "POST", url,
                        headers=self._auth_headers({
                            "X-Upload-Token": upload_token,
                            "X-Recipient": recipient,
                            "X-Offset": str(offset),
                            "X-Total-Size": str(total),
                        }),
                        body=chunk,
                    )
                    if status == 201:
                        # 全部块上传完成, 返回 token
                        token = _read_json_body(body).get("token")
                        self._maybe_progress(progress_cb, total, total)
                        if not token:
                            return {"error": "服务端返回 201 但缺少 token"}
                        return {"token": token}
                    if status == 409:
                        # 断点续传协商: 服务端已有部分数据, 对齐到协商 offset
                        data = _read_json_body(body)
                        new_offset = data.get("offset")
                        if not isinstance(new_offset, int) or new_offset < 0:
                            return {"error": "服务端返回非法续传偏移"}
                        if new_offset >= total:
                            # 服务端已有完整数据, 本次续传视为成功
                            self._maybe_progress(progress_cb, total, total)
                            return {"error": "服务端续传偏移超出文件大小, 无法续传"}
                        if new_offset <= offset:
                            # 服务端不前进 (倒退或原地踏步), 防止死循环
                            return {"error": "服务端续传偏移未前进, 拒绝继续"}
                        offset = new_offset
                        self._maybe_progress(progress_cb, offset, total)
                        continue
                    if status >= 400:
                        return {"error": f"上传失败: HTTP {status} ({body.decode('utf-8', 'ignore')[:200]})"}
                    return {"error": f"上传异常: 意外状态码 HTTP {status}"}
        except FileClientError as e:
            return {"error": f"上传网络错误: {e}"}
        except OSError as e:
            return {"error": f"读取文件失败: {e}"}
        return {"error": "上传未完成"}

    # ------------------------------------------------------------------
    # 下载
    # ------------------------------------------------------------------
    def download(self, token: str, dest_dir: str, progress_cb=None):
        """下载密文到 dest_dir/<token>.bin (临时名, 由调用方解密后重命名)。

        支持 Range 断点续传: 目标文件已部分存在时, 先 HEAD 取服务端 size,
        从本地已有大小发起 Range 请求并追加写。
        成功: {"path": str, "size": int}   失败: {"error": 中文原因}
        """
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            return {"error": "非法文件 token"}
        dest_dir = os.path.realpath(dest_dir)
        if not os.path.isdir(dest_dir):
            return {"error": f"目标目录不存在: {dest_dir}"}
        dest = os.path.join(dest_dir, f"{token}.bin")
        url = f"{self.server_url}/v1/files/download/{urllib.parse.quote(token)}"
        self._last_progress = 0.0

        # 1) HEAD 获取服务端文件大小
        try:
            status, headers, body = self._http_raw(
                "HEAD", url, headers=self._auth_headers())
        except FileClientError as e:
            return {"error": f"查询文件失败: {e}"}
        if status == 404:
            return {"error": "not found"}
        if status != 200:
            return {"error": f"查询文件失败: HTTP {status}"}
        server_size = 0
        if body:
            server_size = int(_read_json_body(body).get("size") or 0)
        else:
            try:
                server_size = int(headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                server_size = 0
        if server_size <= 0:
            return {"error": "服务端未返回文件大小"}

        # 2) 本地已存在的部分 (断点续传基础)
        local_size = os.path.getsize(dest) if os.path.exists(dest) else 0
        if local_size > server_size:
            # 本地比服务端还大: 数据不一致, 从头重下
            local_size = 0
        if local_size >= server_size:
            self._maybe_progress(progress_cb, server_size, server_size)
            return {"path": dest, "size": local_size}

        # 3) Range 请求续传剩余部分
        req_headers = self._auth_headers()
        if local_size > 0:
            req_headers["Range"] = f"bytes={local_size}-"
        try:
            status, headers, body = self._http_raw(
                "GET", url, headers=req_headers)
        except FileClientError as e:
            return {"error": f"下载网络错误: {e}"}
        if status == 404:
            return {"error": "not found"}
        if status not in (200, 206):
            return {"error": f"下载失败: HTTP {status}"}

        if status == 206 and local_size > 0:
            # 部分内容: 追加写
            content_range = headers.get("Content-Range", "")
            # 校验起始偏移与服务端协商一致 (格式: bytes start-end/total)
            m = re.match(r"bytes\s+(\d+)-", content_range)
            if m and int(m.group(1)) != local_size:
                return {"error": "服务端 Range 响应偏移不匹配, 放弃续传"}
            with open(dest, "ab") as f:
                f.write(body)
        else:
            # 200 整文件: 覆盖写
            with open(dest, "wb") as f:
                f.write(body)
            local_size = 0
            if status == 206:
                local_size = 0  # 无 Range 请求但返回 206, 以整文件计

        final_size = local_size + len(body)
        # 服务端 size 若与已下载不符, 提示 (不强制失败, 由调用方校验 sha256)
        if final_size != server_size:
            # 尝试补齐: 简单起见直接报错, 让调用方重试
            return {"error": f"下载不完整: 本地 {final_size} != 服务端 {server_size}"}
        self._maybe_progress(progress_cb, final_size, final_size)
        return {"path": dest, "size": final_size}

    # ------------------------------------------------------------------
    # 元信息
    # ------------------------------------------------------------------
    def head(self, token: str):
        """HEAD 查询文件元信息。
        成功: {"size": int}   不存在: {"error": "not found"}   失败: {"error": str}
        """
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            return {"error": "非法文件 token"}
        url = f"{self.server_url}/v1/files/download/{urllib.parse.quote(token)}"
        try:
            status, headers, body = self._http_raw(
                "HEAD", url, headers=self._auth_headers())
        except FileClientError as e:
            return {"error": str(e)}
        if status == 404:
            return {"error": "not found"}
        if status != 200:
            return {"error": f"HTTP {status}"}
        if body:
            data = _read_json_body(body)
            size = data.get("size")
            if isinstance(size, int):
                return {"size": size}
        try:
            return {"size": int(headers.get("Content-Length") or 0)}
        except (TypeError, ValueError):
            return {"error": "响应缺少文件大小"}

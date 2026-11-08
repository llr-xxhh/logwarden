"""远程日志拉取：SSH/SFTP · SMB · HTTP(S)。

三条约束，与 DESIGN.md 决策 12 对齐：

1. **凭据只在内存里活一次连接**——不写磁盘、不进库、不进日志。进程退出即失。
2. **按块流式读**——远端文件整份进内存会把进程打死（1 GB 的 Security.evtx）。
3. **拉取是后台任务**——接口立刻返回 job_id，前端轮询进度，可中途取消。

三个协议共用一套抽象：`expand()` 展开通配、`open()` 返回可读流、`sample()`
取一段样本。上层的 `ConcatStream` 把多份轮转文件首尾相接成一个流，直接喂给
`Importer.import_stream()`，后者本来就支持任意 BinaryIO。
"""
from __future__ import annotations

import base64
import fnmatch
import gzip
import io
import ntpath
import posixpath
import re
import stat as statmod
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from typing import Any, BinaryIO, Callable, Iterable

CONNECT_TIMEOUT = 12
SAMPLE_BYTES = 256 * 1024
# 只为支持 Importer 开头那次 read(8) + seek(0)；超过这个量就不再回退，直接拒绝
HEAD_KEEP = 64 * 1024
DEFAULT_PORTS = {"ssh": 22, "smb": 445, "http": 80}
PROTOCOLS = ("ssh", "smb", "http")

# 界面上认证方式写的是中文，这里做一次归一，避免前端文案一改后端就崩
AUTH_ALIASES = {
    "key": "key", "密钥": "key", "密钥（推荐 · 不落库）": "key", "密钥（推荐）": "key",
    "password": "password", "密码": "password", "密码（仅本次连接，不保存）": "password",
    "session": "session", "复用现有会话": "session", "复用会话": "session",
}

# 进程内的"最近一次成功连接"。选「复用现有会话」时从这里取，不落盘。
_LAST_AUTH: dict[str, dict[str, Any]] = {}
# 主机指纹（TOFU）。和凭据分开存：淘汰逻辑按 at 排序，混在一起会踩 KeyError。
_KNOWN_HOSTS: dict[str, str] = {}
_LAST_LOCK = threading.Lock()
# 会话凭据的有效期：过了就当没有，防止进程长挂时凭据一直可被复用
_SESSION_TTL = 600.0


class PullError(RuntimeError):
    """远端侧的问题，消息直接给用户看。"""


class Cancelled(RuntimeError):
    """用户点了取消。"""


def new_job_id() -> str:
    return "j" + uuid.uuid4().hex[:12]


# --- 请求归一化 -------------------------------------------------------------

def _port(value: Any, protocol: str) -> int:
    try:
        port = int(value or 0)
    except (TypeError, ValueError):
        port = 0
    return port or DEFAULT_PORTS.get(protocol, 0)


def normalize(data: dict[str, Any]) -> dict[str, Any]:
    """把前端提交的表单整理成内部 spec，顺手做校验。"""
    if not isinstance(data, dict):
        raise ValueError("请求体必须是对象")
    protocol = str(data.get("protocol") or "ssh").strip().lower()
    protocol = {"sftp": "ssh", "https": "http", "smb2": "smb"}.get(protocol, protocol)
    if protocol not in PROTOCOLS:
        raise ValueError("不支持的协议：%s" % protocol)

    host = str(data.get("host") or "").strip()
    if not host:
        raise ValueError("请填写主机地址")
    if any(ch in host for ch in "\r\n\t "):
        raise ValueError("主机地址含空白字符")

    auth = AUTH_ALIASES.get(str(data.get("auth") or "password").strip(), "password")
    path = str(data.get("path") or "").strip()
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    key_text = str(data.get("key_text") or "")
    key_path = str(data.get("key_path") or "").strip()

    if protocol == "http":
        if not path:
            raise ValueError("请填写远端路径（URL 路径部分）")
        raw_port = _int_or_zero(data.get("port"))
        url = _http_url(host, path, raw_port, data.get("tls"))
        port = raw_port or (443 if url.startswith("https://") else 80)
        spec = {"protocol": protocol, "host": host, "port": port,
                "path": path, "url": url, "username": username, "password": password,
                "auth": "password" if (username or password) else "none"}
        return spec

    if not path:
        raise ValueError("请填写远端路径")
    # SMB 路径格式不用等连上才知道错，先挡一道，省一次 12 秒超时
    if protocol == "smb":
        try:
            smb_unc(host, path)
        except PullError as exc:
            raise ValueError(str(exc)) from exc
    if auth == "password" and not password:
        raise ValueError("密码认证需要填写密码")
    if auth == "key" and not (key_text or key_path):
        raise ValueError("密钥认证需要选择密钥文件或粘贴私钥")
    if auth == "session":
        slot = "%s:%s:%s" % (protocol, host, _port(data.get("port"), protocol))
        with _LAST_LOCK:
            cached = _LAST_AUTH.get(slot)
            if cached and time.time() - cached.get("at", 0) > _SESSION_TTL:
                _LAST_AUTH.pop(slot, None)   # 过期即焚，不留给下次
                cached = None
        if not cached:
            raise ValueError("没有可复用的会话（超过 10 分钟已失效），请先用密码或密钥连接一次")
        auth = cached["auth"]
        password = cached.get("password") or password
        key_text = cached.get("key_text") or key_text
        key_path = cached.get("key_path") or key_path
        username = username or cached.get("username") or ""

    if not username:
        raise ValueError("请填写用户名")

    return {
        "protocol": protocol,
        "host": host,
        "port": _port(data.get("port"), protocol),
        "username": username,
        "password": password,
        "auth": auth,
        "key_text": key_text,
        "key_path": key_path,
        "key_passphrase": str(data.get("key_passphrase") or ""),
        "path": path,
        "url": "",
    }


def _int_or_zero(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _http_url(host: str, path: str, port: int, tls: Any) -> str:
    """host 可以是纯域名，也可以直接是 http(s)://... 前缀。

    port 为 0 表示用户没填：同 scheme 默认端口，不进 URL。
    """
    if "://" in host:
        parsed = urllib.parse.urlsplit(host.rstrip("/"))
        netloc = parsed.netloc
        # 用户把 scheme 写全了，但表单里另填了端口：补进 netloc，别把端口丢了
        has_port = ":" in netloc.rsplit("]", 1)[-1]
        if port and port not in (80, 443) and not has_port:
            netloc = "%s:%d" % (netloc, port)
        if not path.startswith("/"):
            path = "/" + path
        return "%s://%s%s%s" % (parsed.scheme, netloc, parsed.path.rstrip("/"), path)
    scheme = "https" if (tls is True or str(tls).lower() in ("1", "true", "yes", "on")) else "http"
    if not path.startswith("/"):
        path = "/" + path
    netloc = host if port in (0, 80, 443) else "%s:%d" % (host, port)
    return "%s://%s%s" % (scheme, netloc, path)


def remember_auth(spec: dict[str, Any]) -> None:
    """连接成功后记住凭据，供「复用现有会话」用；只在内存。"""
    key = "%s:%s:%s" % (spec["protocol"], spec["host"], spec["port"])
    with _LAST_LOCK:
        _LAST_AUTH[key] = {
            "auth": spec["auth"], "username": spec.get("username"),
            "password": spec.get("password"), "key_text": spec.get("key_text"),
            "key_path": spec.get("key_path"), "at": time.time(),
        }
        # 只留最近 8 条，避免进程长期挂着时越攒越多
        if len(_LAST_AUTH) > 8:
            for old in sorted(_LAST_AUTH, key=lambda k: _LAST_AUTH[k]["at"])[:-8]:
                _LAST_AUTH.pop(old, None)


def _safe_host(spec: dict[str, Any]) -> str:
    """给前端看的连接串，不含任何凭据。"""
    user = spec.get("username") or ""
    prefix = (user + "@") if user else ""
    if spec["protocol"] == "http":
        return spec.get("url") or spec["host"]
    return "%s%s:%s" % (prefix, spec["host"], spec["port"])


# --- 压缩 / 解码 ------------------------------------------------------------

class _GzipPiece:
    """把 gzip 流包成普通可读对象，close 时连底层句柄一起关。"""

    def __init__(self, raw: BinaryIO):
        self._raw = raw
        self._gz = gzip.GzipFile(fileobj=raw, mode="rb")

    def read(self, n: int = -1) -> bytes:
        return self._gz.read(n)

    def readinto(self, buf) -> int:
        data = self._gz.read(len(buf))
        buf[:len(data)] = data
        return len(data)

    def close(self) -> None:
        try:
            self._gz.close()
        finally:
            try:
                self._raw.close()
            except Exception:
                pass


def decode_sample(head: bytes) -> bytes:
    """样本若是 gzip，就地解压；截断的数据用 decompressobj 容错。"""
    if head[:2] != b"\x1f\x8b":
        return head
    try:
        return gzip.decompress(head)
    except Exception:
        try:
            obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
            return obj.decompress(head)
        except Exception:
            return b""


def estimate_lines(data: bytes, raw_len: int, size: int) -> int:
    """按样本的平均行长推算总行数，只求数量级。

    `data` 是解压后的样本，`raw_len` 是它对应的网络字节数。两者之比就是压缩比，
    用来把压缩后的总大小折算成解压后的总大小——否则读 gzip 会低估好几倍。
    """
    if not data or not size:
        return 0
    newlines = data.count(b"\n")
    if not newlines:
        return 1
    average = len(data) / newlines
    total = size * (len(data) / raw_len) if raw_len and raw_len < len(data) else size
    return max(1, int(total / average))


def lines_from_sample(sample: bytes, limit: int = 3) -> list[str]:
    text = sample.decode("utf-8", "replace")
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        out.append(line[:300])
        if len(out) >= limit:
            break
    return out


def _has_glob(pattern: str) -> bool:
    return bool(re.search(r"[*?\[]", pattern))


# --- 文件系统抽象 -----------------------------------------------------------

class RemoteFS:
    """远端只读文件系统的统一门面。三个协议各实现一份。"""

    protocol = ""
    banner = ""

    def close(self) -> None:  # pragma: no cover - 子类实现
        pass

    def expand(self, pattern: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def open_raw(self, path: str) -> BinaryIO:
        raise NotImplementedError

    def open(self, path: str) -> BinaryIO:
        """按扩展名决定是否解压：上层拿到的永远是明文字节流。"""
        raw = self.open_raw(path)
        return _GzipPiece(raw) if path.lower().endswith(".gz") else raw

    def sample(self, path: str, size: int = SAMPLE_BYTES) -> dict[str, Any]:
        """返回 {"data": 解压后样本, "raw_len": 网络字节数, "compressed": 是否解压过}。"""
        raw = self.open_raw(path)
        try:
            head = raw.read(size) or b""
        finally:
            try:
                raw.close()
            except Exception:
                pass
        data = decode_sample(head) if path.lower().endswith(".gz") else head
        return {"data": data, "raw_len": len(head), "compressed": data is not head}


class _SftpFS(RemoteFS):
    protocol = "ssh"

    def __init__(self, spec: dict[str, Any]):
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - 依赖缺失时才会走到
            raise PullError("缺少 paramiko 组件，执行 .venv\\Scripts\\pip install paramiko") from exc
        self._paramiko = paramiko
        client = paramiko.SSHClient()
        # 首次连接无法验证指纹，先信任；下面再做 TOFU 比对，变了就断开
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict[str, Any] = {
            "hostname": spec["host"],
            "port": spec["port"],
            "username": spec["username"],
            "timeout": CONNECT_TIMEOUT,
            "banner_timeout": CONNECT_TIMEOUT,
            "auth_timeout": CONNECT_TIMEOUT,
            "look_for_keys": False,   # 否则会拿本机 ~/.ssh 的密钥乱试，行为和用户预期不符
            "allow_agent": False,
        }
        if spec["auth"] == "key":
            kwargs["pkey"] = self._load_key(spec)
            kwargs["passphrase"] = spec.get("key_passphrase") or None
        else:
            kwargs["password"] = spec.get("password") or ""
        try:
            client.connect(**kwargs)
        except paramiko.AuthenticationException as exc:
            client.close()
            raise PullError("认证失败：用户名、密码或密钥不正确") from exc
        except paramiko.SSHException as exc:
            client.close()
            raise PullError("SSH 协商失败：%s" % exc) from exc
        except OSError as exc:
            client.close()
            raise PullError("连不上 %s:%s（%s）" % (spec["host"], spec["port"], exc)) from exc
        transport = client.get_transport()
        if transport is None:
            client.close()
            raise PullError("SSH 通道建立失败")
        transport.set_keepalive(20)
        self._client = client
        self._transport = transport
        self._sftp = paramiko.SFTPClient.from_transport(transport)
        if self._sftp is None:
            client.close()
            raise PullError("SFTP 子系统不可用（服务器可能没开 sftp）")
        # 无超时读会让挂起的连接把线程和写锁一起拖死；keepalive 只保连接不断，
        # 这里给每次读一个上限，网络断开时抛 timeout 而不是永远等待
        self._sftp.get_channel().settimeout(30)
        self.banner = transport.remote_version or "SSH"
        try:
            self._fingerprint_check(spec["host"], spec["port"], transport)
        except Exception:
            client.close()   # 指纹不符直接断开，别把连接留在后台
            raise

    def _load_key(self, spec: dict[str, Any]):
        paramiko = self._paramiko
        text = spec.get("key_text") or ""
        path = spec.get("key_path") or ""
        passphrase = spec.get("key_passphrase") or None
        if path and not text:
            try:
                return paramiko.PKey.from_path(path, password=passphrase)
            except Exception as exc:
                # 异常原文可能带回私钥内容片段，只给用户定位信息，细节进服务端日志
                raise PullError("读取密钥失败（%s），请确认文件存在且口令正确" % path) from exc
        stream = io.StringIO(text)
        last: Exception | None = None
        classes = [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey]
        dss = getattr(paramiko, "DSSKey", None)   # DSA 已废弃，新版可能整类移除
        if dss is not None:
            classes.append(dss)
        for cls in classes:
            stream.seek(0)
            try:
                return cls.from_private_key(stream, password=passphrase)
            except Exception as exc:  # 换下一个类型再试
                last = exc
        raise PullError("无法识别这份私钥（支持 RSA / ECDSA / Ed25519），请确认内容完整、未加密或口令正确")

    @staticmethod
    def _fingerprint_check(host: str, port: int, transport) -> None:
        """TOFU：同一 host:port 第二次连到不同指纹就拒绝，挡住中间人。"""
        try:
            key = transport.get_remote_server_key()
            digest = key.get_fingerprint().hex()
        except Exception as exc:
            # 指纹都拿不到还放行，等于跳过防中间人检查——宁可连不上
            raise PullError("无法读取主机指纹，连接中止（SSH 协商异常：%s）" % exc) from exc
        slot = "%s:%s" % (host, port)
        with _LAST_LOCK:
            known = _KNOWN_HOSTS.get(slot)
            if known and known != digest:
                raise PullError(
                    "主机指纹变了：上次 %s，这次 %s。可能存在中间人，确认无误后重启程序再连。"
                    % (known[:16], digest[:16])
                )
            _KNOWN_HOSTS[slot] = digest

    def expand(self, pattern: str) -> list[dict[str, Any]]:
        if not _has_glob(pattern):
            return [self._one(pattern)]
        dirname = posixpath.dirname(pattern) or "."
        base = posixpath.basename(pattern)
        try:
            entries = self._sftp.listdir_attr(dirname)
        except IOError as exc:
            raise PullError("列目录失败 %s：%s" % (dirname, exc)) from exc
        out = []
        for item in entries:
            if not fnmatch.fnmatch(item.filename, base):
                continue
            if item.st_mode is not None and statmod.S_ISDIR(item.st_mode):
                continue
            out.append({
                "path": posixpath.join(dirname, item.filename),
                "size": int(item.st_size or 0),
                "mtime": int(item.st_mtime or 0),
            })
        if not out:
            raise PullError("远端没有匹配 %s 的文件" % pattern)
        # 轮转文件按修改时间升序拼，时间线才连得上
        out.sort(key=lambda x: (x["mtime"], x["path"]))
        return out

    def _one(self, path: str) -> dict[str, Any]:
        try:
            info = self._sftp.stat(path)
        except IOError as exc:
            raise PullError("远端文件不存在或不可读：%s（%s）" % (path, exc)) from exc
        if statmod.S_ISDIR(info.st_mode or 0):
            raise PullError("%s 是目录，请写到文件名或用通配" % path)
        return {"path": path, "size": int(info.st_size or 0), "mtime": int(info.st_mtime or 0)}

    def open_raw(self, path: str) -> BinaryIO:
        try:
            handle = self._sftp.open(path, "rb")
        except IOError as exc:
            raise PullError("打开远端文件失败 %s：%s" % (path, exc)) from exc
        # 不预取的话每 32 KB 发一个请求，拉 1 GB 会被 RTT 拖死
        try:
            handle.prefetch()
        except Exception:
            pass
        return handle

    def close(self) -> None:
        for closer in (getattr(self, "_sftp", None), getattr(self, "_client", None)):
            if closer is not None:
                try:
                    closer.close()
                except Exception:
                    pass


def smb_unc(host: str, path: str) -> str:
    """把用户填的路径转成 UNC。支持 \\\\host\\share\\... 与 C:\\Windows\\... 两种写法。"""
    p = (path or "").strip().replace("/", "\\")
    if p.startswith("\\\\"):
        # 已经是 UNC：保留开头两个反斜杠，其余重复的压成一个
        head, _, rest = p[2:].partition("\\")
        return "\\\\" + head + ("\\" + re.sub(r"\\{2,}", "\\\\", rest) if rest else "")
    p = re.sub(r"\\{2,}", "\\\\", p)
    drive = re.match(r"^([A-Za-z]):\\?(.*)$", p)
    if drive:
        # C:\Windows\... → \\host\C$\Windows\...
        return "\\\\%s\\%s$\\%s" % (host, drive.group(1).upper(), drive.group(2))
    raise PullError(
        "SMB 路径要写成 \\\\主机\\共享\\子路径，或 C:\\Windows\\... 形式；不能直接用 /var/log/..."
    )


class _SmbFS(RemoteFS):
    protocol = "smb"

    def __init__(self, spec: dict[str, Any]):
        try:
            import smbclient
        except ImportError as exc:  # pragma: no cover
            raise PullError("缺少 smbprotocol 组件，执行 .venv\\Scripts\\pip install smbprotocol") from exc
        self._c = smbclient
        self._host = spec["host"]
        username = spec.get("username") or ""
        try:
            smbclient.register_session(
                self._host,
                username=username,
                password=spec.get("password") or "",
                port=spec["port"] or 445,
                connection_timeout=CONNECT_TIMEOUT,
            )
        except Exception as exc:
            raise PullError("SMB 连接失败 %s:%s（%s）" % (spec["host"], spec["port"], exc)) from exc
        self.banner = "SMB " + self._host

    def _unc(self, path: str) -> str:
        return smb_unc(self._host, path)

    def expand(self, pattern: str) -> list[dict[str, Any]]:
        unc = self._unc(pattern)
        if not _has_glob(pattern):
            try:
                info = self._c.stat(unc)
            except Exception as exc:
                raise PullError("远端文件不存在或不可读：%s（%s）" % (pattern, exc)) from exc
            if getattr(info, "is_directory", lambda: False)():
                raise PullError("%s 是目录，请写到文件名或用通配" % pattern)
            return [{"path": pattern, "size": int(info.st_size or 0),
                     "mtime": int(getattr(info, "st_mtime", 0) or 0)}]

        dirname, base = ntpath.split(unc)
        dir_unc = dirname or "\\\\%s" % self._host
        # 让服务器侧用通配筛，比全列回来再匹配省一次往返
        try:
            entries = self._c.scandir(dir_unc, search_pattern=base)
        except Exception as exc:
            raise PullError("列目录失败 %s：%s" % (dirname, exc)) from exc
        out = []
        shown_dir = ntpath.dirname(pattern) or ""
        for entry in entries:
            if not fnmatch.fnmatch(entry.name, base):
                continue
            try:
                is_dir = entry.is_dir()
            except Exception:
                is_dir = False   # 目录判断失败时当文件处理，交给下面的 stat 决定
            if is_dir:
                continue
            try:
                info = entry.stat()
            except Exception:
                # stat 失败不丢条目：以 size=0 进清单，打开阶段自然失败并进 skipped。
                # 直接 continue 会让用户以为拉全了，实际少文件且无处可查
                info = None
            shown = ntpath.join(shown_dir, entry.name) if shown_dir else entry.name
            out.append({"path": shown,
                        "size": int(info.st_size or 0) if info else 0,
                        "mtime": int(getattr(info, "st_mtime", 0) or 0) if info else 0})
        if not out:
            raise PullError("远端没有匹配 %s 的文件" % pattern)
        out.sort(key=lambda x: (x["mtime"], x["path"]))
        return out

    def open_raw(self, path: str) -> BinaryIO:
        try:
            return self._c.open_file(self._unc(path), mode="rb")
        except Exception as exc:
            raise PullError("打开远端文件失败 %s：%s" % (path, exc)) from exc

    def close(self) -> None:
        try:
            self._c.delete_session(self._host)
        except Exception:
            pass


class _HttpFS(RemoteFS):
    protocol = "http"

    def __init__(self, spec: dict[str, Any]):
        self.url = spec["url"]
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme not in ("http", "https"):
            raise PullError("只支持 http / https")
        self.banner = "HTTP " + (parsed.hostname or "")
        self._headers: dict[str, str] = {"User-Agent": "LogWarden/remote"}
        user = spec.get("username") or ""
        password = spec.get("password") or ""
        if user or password:
            token = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
            self._headers["Authorization"] = "Basic " + token

    def _request(self, method: str, extra: dict[str, str] | None = None):
        headers = dict(self._headers)
        headers.update(extra or {})
        req = urllib.request.Request(self.url, method=method, headers=headers)
        try:
            return urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT)
        except urllib.error.HTTPError as exc:
            raise PullError("HTTP %s：%s" % (exc.code, exc.reason)) from exc
        except urllib.error.URLError as exc:
            raise PullError("连不上 %s（%s）" % (self.url, exc.reason)) from exc

    def expand(self, pattern: str) -> list[dict[str, Any]]:
        if _has_glob(pattern):
            raise PullError("HTTP 不支持通配，请给出确切的文件 URL")
        size, mtime = 0, 0
        try:
            with self._request("HEAD") as resp:
                size = int(resp.headers.get("Content-Length") or 0)
                mtime = _http_mtime(resp.headers.get("Last-Modified"))
        except PullError:
            # 不少服务端禁 HEAD，退一步用 Range 探一下总长
            try:
                with self._request("GET", {"Range": "bytes=0-0"}) as resp:
                    size = _content_range_total(resp.headers.get("Content-Range")) or int(
                        resp.headers.get("Content-Length") or 0)
                    mtime = _http_mtime(resp.headers.get("Last-Modified"))
            except PullError as exc:
                raise PullError("无法读取远端文件信息：%s" % exc) from exc
        return [{"path": self.url, "size": size, "mtime": mtime}]

    def open_raw(self, path: str) -> BinaryIO:
        # 始终带 Range：服务端支持就流式吐，不支持也会回 200 整份，urllib 一样能读
        return self._request("GET")

    def sample(self, path: str, size: int = SAMPLE_BYTES) -> dict[str, Any]:
        with self._request("GET", {"Range": "bytes=0-%d" % (size - 1)}) as resp:
            head = resp.read(size) or b""
        data = decode_sample(head)
        return {"data": data, "raw_len": len(head), "compressed": data is not head}

    def close(self) -> None:
        pass


def _http_mtime(value: str | None) -> int:
    if not value:
        return 0
    try:
        from email.utils import parsedate_to_datetime
        return int(parsedate_to_datetime(value).timestamp())
    except Exception:
        return 0


def _content_range_total(value: str | None) -> int:
    if not value or "/" not in value:
        return 0
    tail = value.rsplit("/", 1)[-1].strip()
    return int(tail) if tail.isdigit() else 0


def open_fs(spec: dict[str, Any]) -> RemoteFS:
    if spec["protocol"] == "ssh":
        return _SftpFS(spec)
    if spec["protocol"] == "smb":
        return _SmbFS(spec)
    if spec["protocol"] == "http":
        return _HttpFS(spec)
    raise PullError("不支持的协议：%s" % spec["protocol"])


# --- 多文件拼接流 -----------------------------------------------------------

class ConcatStream(io.RawIOBase):
    """把多份轮转文件接成一个流喂给 importer。

    只实现 `seek(0)`——importer 的 `_peek()` 读完文件头要复位。已读字节先攒在
    `_head` 里，复位时直接回吐，不用重连一次远端。超过 HEAD_KEEP 的 seek 一律拒绝，
    正常的导入流程碰不到。
    """

    def __init__(self, pieces: list[dict[str, Any]], on_open: Callable[[dict[str, Any]], None] | None = None,
                 on_read: Callable[[int], None] | None = None,
                 cancel: Callable[[], bool] | None = None,
                 on_skip: Callable[[dict[str, Any], Exception], None] | None = None):
        super().__init__()
        self._pieces = pieces
        self._index = 0
        self._fh: BinaryIO | None = None
        self._on_open = on_open
        self._on_read = on_read
        self._cancel = cancel
        # 给了 on_skip 就表示「单个文件打不开不致命，记一笔继续下一个」。
        # 真实环境里 /var/log 常混着 root 专属文件，ai 这种普通账号读不了其中一个，
        # 不该让整批 14 个文件全废。
        self._on_skip = on_skip
        self._head = bytearray()
        self._total = 0
        self._pushback = b""

    def readable(self) -> bool:
        return True

    def _current(self) -> BinaryIO | None:
        while self._fh is None:
            if self._index >= len(self._pieces):
                return None
            piece = self._pieces[self._index]
            self._index += 1
            if self._on_open is not None:
                self._on_open(piece)
            try:
                self._fh = piece["opener"]()
            except Exception as exc:
                if self._on_skip is None:
                    raise
                self._on_skip(piece, exc)
                continue
        return self._fh

    def readinto(self, buf) -> int:
        if self._cancel is not None and self._cancel():
            raise Cancelled("用户取消")
        if self._pushback:
            n = min(len(buf), len(self._pushback))
            buf[:n] = self._pushback[:n]
            self._pushback = self._pushback[n:]
            return n
        while True:
            handle = self._current()
            if handle is None:
                return 0
            try:
                data = handle.read(len(buf))
            except Exception as exc:
                if self._cancel is not None and self._cancel():
                    raise Cancelled("用户取消") from exc
                raise PullError("读取远端数据失败：%s" % exc) from exc
            if data:
                buf[:len(data)] = data
                self._total += len(data)
                if len(self._head) < HEAD_KEEP:
                    self._head.extend(data[:HEAD_KEEP - len(self._head)])
                if self._on_read is not None:
                    self._on_read(len(data))
                return len(data)
            try:
                handle.close()
            except Exception:
                pass
            self._fh = None

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence != io.SEEK_SET or offset != 0:
            raise io.UnsupportedOperation("远程流只能回到开头")
        if self._total == 0 and not self._pushback:
            return 0
        if self._total > HEAD_KEEP:
            raise io.UnsupportedOperation("已读过 %d 字节，无法回到开头" % self._total)
        # _peek 只读 8 字节，回吐缓冲即可，不必重开连接
        self._pushback = bytes(self._head) + self._pushback
        self._head.clear()
        self._total = 0
        return 0

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None
        super().close()


# --- 任务 -------------------------------------------------------------------

class Job:
    __slots__ = ("id", "kind", "state", "created_at", "started_at", "finished_at",
                 "target", "protocol", "files_total", "files_done", "bytes_total",
                 "bytes_done", "rows", "failed", "current_file", "message", "error",
                 "result", "skipped", "task_id", "_cancel")

    def __init__(self, kind: str, spec: dict[str, Any]):
        self.id = new_job_id()
        self.kind = kind              # probe / pull
        self.state = "pending"        # pending / running / done / failed / cancelled
        self.task_id = ""             # pull 归属的任务，probe 为空
        self.created_at = time.time()
        self.started_at = 0.0
        self.finished_at = 0.0
        self.protocol = spec.get("protocol") or ""
        self.target = _safe_host(spec) if spec else ""
        self.files_total = 0
        self.files_done = 0
        self.bytes_total = 0
        self.bytes_done = 0
        self.rows = 0
        self.failed = 0
        self.current_file = ""
        self.message = "等待开始"
        self.error = ""
        self.result: Any = None
        self.skipped: list[str] = []
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def snapshot(self) -> dict[str, Any]:
        elapsed = ((self.finished_at or time.time()) - (self.started_at or self.created_at))
        if self.state == "done":
            percent = 100
        elif self.bytes_total:
            percent = int(min(99, self.bytes_done * 100 / self.bytes_total))
        elif self.files_total:
            percent = int(min(99, self.files_done * 100 / self.files_total))
        else:
            percent = 0
        return {
            "id": self.id, "kind": self.kind, "state": self.state,
            "protocol": self.protocol, "target": self.target,
            "files_total": self.files_total, "files_done": self.files_done,
            "bytes_total": self.bytes_total, "bytes_done": self.bytes_done,
            "rows": self.rows, "failed": self.failed,
            "current_file": self.current_file, "message": self.message,
            "error": self.error, "percent": percent,
            "skipped": list(self.skipped),
            "elapsed": round(elapsed, 1),
            "result": self.result if self.state in ("done", "failed", "cancelled") else None,
        }


class Jobs:
    """进程内的任务表。不落盘：进程重启后旧 job 查不到是正常的。"""

    def __init__(self, keep: int = 40):
        self._items: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._keep = keep
        # DuckDB 单进程一把写锁，两个 pull 同时写会互相卡死，直接串行
        self.write_lock = threading.Lock()

    def add(self, job: Job) -> Job:
        with self._lock:
            self._items[job.id] = job
            finished = [j for j in self._items.values() if j.state in ("done", "failed", "cancelled")]
            if len(finished) > self._keep:
                for old in sorted(finished, key=lambda j: j.created_at)[:-self._keep]:
                    self._items.pop(old.id, None)
        return job

    def get(self, job_id: str) -> Job:
        with self._lock:
            job = self._items.get(job_id)
        if job is None:
            raise KeyError("任务不存在或已过期")
        return job


JOBS = Jobs()


# --- 探测 -------------------------------------------------------------------

def probe(data: dict[str, Any]) -> dict[str, Any]:
    """连通性 + 文件清单 + 行数估算 + 几行样本，一次给全。"""
    spec = normalize(data)
    started = time.time()
    fs = open_fs(spec)
    try:
        files = fs.expand(spec["path"])
        total = sum(int(f["size"]) for f in files)
        # 多文件时取最后一个（最新的那份），最能反映当前格式
        target = files[-1]["path"] if len(files) > 1 else files[0]["path"]
        info = fs.sample(target)
        est = estimate_lines(info["data"], info["raw_len"], total)
        sample = lines_from_sample(info["data"])
        if spec["auth"] != "none":
            remember_auth(spec)
        notes = []
        if info["compressed"]:
            notes.append("压缩文件，行数是按样本压缩比推算的")
        if len(files) > 1:
            notes.append("匹配 %d 个文件，按修改时间从旧到新拼接" % len(files))
        if total > 500 * 1024 * 1024:
            notes.append("总量超过 500 MB，导入会分批，耗时取决于带宽")
        return {
            "ok": True,
            "protocol": spec["protocol"],
            "target": _safe_host(spec),
            "banner": fs.banner,
            "files": [{**f, "name": posixpath.basename(f["path"].replace("\\", "/"))} for f in files[:200]],
            "files_total": len(files),
            "total_size": total,
            "est_lines": est,
            "sample": sample,
            "notes": notes,
            "elapsed": round(time.time() - started, 2),
        }
    finally:
        fs.close()


# --- 拉取 -------------------------------------------------------------------

def start_pull(data: dict[str, Any], importer, task_id: str, source_id: str,
               fmt: str, encoding: str = "utf-8") -> Job:
    """建 job、起线程，立刻返回。真正的导入在后台跑。"""
    spec = normalize(data)
    if not task_id:
        raise ValueError("缺少任务 id")
    if not source_id:
        raise ValueError("请选择归入哪个日志源")
    if not fmt:
        raise ValueError("请选择解析格式")

    job = Job("pull", spec)
    job.task_id = task_id
    job.message = "准备连接"
    JOBS.add(job)
    thread = threading.Thread(
        target=_run_pull, args=(job, spec, importer, task_id, source_id, fmt, encoding),
        name="remote-pull-" + job.id, daemon=True,
    )
    thread.start()
    return job


def _run_pull(job: Job, spec: dict[str, Any], importer, task_id: str,
              source_id: str, fmt: str, encoding: str) -> None:
    job.state = "running"
    job.started_at = time.time()
    fs: RemoteFS | None = None
    try:
        job.message = "连接 %s" % _safe_host(spec)
        if job.cancelled():
            raise PullError("已取消")   # 提交后立刻取消：别再对目标主机发起认证
        fs = open_fs(spec)
        job.message = "读取文件清单"
        files = fs.expand(spec["path"])
        if job.cancelled():
            fs.close()
            raise PullError("已取消")   # 连接建立后再查一次，别白拉清单
        job.files_total = len(files)
        job.bytes_total = sum(int(f["size"]) for f in files)
        # importer 的单文件上限检查应针对最大单文件，而非轮转文件总和。
        # 10 个 access.log-* 共 3 GB 不应被 500 MB 上限拒绝。
        max_file_size = max((int(f["size"]) for f in files), default=0)
        if not job.files_total:
            raise PullError("没有可拉取的文件")

        pieces = [{
            "path": item["path"],
            "name": posixpath.basename(item["path"].replace("\\", "/")),
            "size": int(item["size"] or 0),
            "opener": (lambda p=item["path"]: fs.open(p)),
        } for item in files]

        state = {"index": 0}
        skipped: list[str] = []

        def on_open(piece: dict[str, Any]) -> None:
            state["index"] += 1
            job.current_file = piece["name"]
            job.message = "拉取 %s（%d/%d）" % (piece["name"], state["index"], job.files_total)
            job.bytes_done = sum(int(x["size"]) for x in pieces[:state["index"] - 1])

        def on_skip(piece: dict[str, Any], exc: Exception) -> None:
            skipped.append(piece["name"])
            job.skipped = list(skipped)
            job.message = "跳过 %s：%s" % (piece["name"], exc)

        def on_read(n: int) -> None:
            job.bytes_done += n
            if job.bytes_total:
                job.bytes_done = min(job.bytes_done, job.bytes_total)

        stream = ConcatStream(pieces, on_open=on_open, on_read=on_read,
                              cancel=job.cancelled, on_skip=on_skip)
        # 内部已按文件解压过，文件名不能再带 .gz，否则 importer 会二次解压
        display = _display_name(spec, files)
        job.message = "解析并入库"
        # 等写锁时必须能响应取消：前一个 pull 卡在网络读上时，
        # 阻塞式 acquire 会让本 job 永远停在 running，取消也打不断
        while True:
            if job.cancelled():
                raise PullError("已取消")
            if JOBS.write_lock.acquire(timeout=0.5):
                break
            job.message = "等待其他拉取完成"
        try:
            job.message = "解析并入库"
            result = importer.import_stream(
                task_id, source_id, fmt, display, stream, max_file_size, encoding)
        finally:
            JOBS.write_lock.release()
        job.rows = int(result.get("rows") or 0)
        job.failed = int(result.get("failed") or 0)
        job.files_done = job.files_total
        job.bytes_done = job.bytes_total
        job.result = result
        if len(skipped) >= job.files_total and job.files_total:
            # 全部文件都打不开：job 判失败，但 import_stream 已经留下一条
            # rows=0 的空导入记录——删掉它，不然界面多一条假成功的批次
            try:
                importer.store.delete_import(task_id, result.get("id") or "")
            except Exception:
                pass
            raise PullError("所有文件都打不开：" + "；".join(skipped[:3]))
        job.state = "done"
        if skipped:
            job.message = "完成：入库 %d 行，跳过 %d 个不可读文件（%s）" % (
                job.rows, len(skipped), "、".join(skipped[:3]))
        else:
            job.message = "完成：入库 %d 行，失败 %d 行" % (job.rows, job.failed)
        if spec["auth"] != "none":
            remember_auth(spec)
    except Cancelled:
        job.state = "cancelled"
        job.message = "已取消；已提交的批次会留在库里，可在导入记录里删除"
    except (PullError, ValueError) as exc:
        job.state = "failed"
        job.error = str(exc)
        job.message = str(exc)
    except Exception as exc:  # 兜底：不让后台线程静默死掉
        job.state = "failed"
        job.error = "%s: %s" % (type(exc).__name__, exc)
        job.message = job.error
    finally:
        job.finished_at = time.time()
        if job.state == "running":
            job.state = "failed"
        try:
            if fs is not None:
                fs.close()
        except Exception:
            pass


def _display_name(spec: dict[str, Any], files: Iterable[dict[str, Any]]) -> str:
    """导入记录里显示的名字：看得懂是哪个主机、哪份日志，扩展名要留住。"""
    items = list(files)
    first = items[0]["path"] if items else spec["path"]
    base = posixpath.basename(first.replace("\\", "/"))
    if spec["protocol"] == "http":
        try:
            base = posixpath.basename(urllib.parse.urlsplit(spec["url"]).path) or "download.log"
        except Exception:
            base = "download.log"
    if base.lower().endswith(".gz"):
        base = base[:-3]
    if len(items) > 1:
        base = base + " 等 %d 个文件" % len(items)
    if not base:
        base = "remote.log"
    return "%s:%s" % (spec["host"], base)


def status(job_id: str) -> dict[str, Any]:
    return JOBS.get(job_id).snapshot()


def active_pull_for(task_id: str) -> Job | None:
    """该任务上还在跑（或排队）的拉取 job。删任务前必须先处理它。"""
    with JOBS._lock:
        for job in JOBS._items.values():
            if job.kind == "pull" and job.task_id == task_id and job.state in ("pending", "running"):
                return job
    return None


def cancel(job_id: str) -> dict[str, Any]:
    job = JOBS.get(job_id)
    if job.state in ("done", "failed", "cancelled"):
        # 已经结束：不动结果。否则「正在取消」会把真实失败原因冲掉，
        # 用户只看到一句取消成功，问题就被藏了。
        return {"ok": False, "id": job.id, "state": job.state}
    job.cancel()
    job.message = "正在取消"
    return {"ok": True, "id": job.id, "state": job.state}

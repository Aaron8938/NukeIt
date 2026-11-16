# -*- coding: utf-8 -*-
"""NukeIt - Windows 强制删除工具

双击 NukeIt.bat 启动，把文件/文件夹拖进控制台窗口，回车即删。
管理员窗口拖不进东西是 Windows 的安全限制（UIPI），所以空回车会去读剪贴板
（资源管理器里 Ctrl+C 复制的文件），直接粘贴路径也认。

删除内核三级降级：
    L1 常规删除      DeleteFileW / RemoveDirectoryW，先剥只读/隐藏/系统属性
    L2 强开句柄删除  CreateFileW(DELETE) + FILE_SHARE_DELETE + DELETE_ON_CLOSE
    L3 重启时删除    MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT) 或写 PendingFileRenameOperations
第一轮删不掉的目标会反查占用进程，结束进程后只重试失败的那部分。
文件夹删不掉时还会去 PEB 里查是谁把它当成了工作目录——这种占用 Restart
Manager 看不见，但足以让目录永远报共享冲突，是「明明没程序开着却删不掉」的元凶。

注意：junction / 符号链接只删链接本身，绝不递归进入目标目录。
"""

import ctypes
import os
import re
import shutil
import sys
import time
import unicodedata
import winreg
from ctypes import wintypes

APP_NAME = "NukeIt"
VERSION = "1.3"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 控制台是 UTF-8，但一旦输出被重定向到文件/管道，Windows 默认会退回 cp936，
# 这时打印 ✓、… 之类的字符会抛 UnicodeEncodeError，直接把删除过程打断。
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SCAN_LIMIT = 200000          # 统计上限，超过就不再数了
RETRY_BUDGET = 120           # 单个目标允许的「占用重试」总次数，防止批量占用时假死
BIG_SIZE = 20 * 1024 ** 3    # 超过 20GB，或
BIG_FILES = 50000            # 超过 5 万个文件，额外要一次 YES

# --------------------------------------------------------------------------
# Win32 常量与函数
# --------------------------------------------------------------------------
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

DELETE = 0x00010000
FILE_READ_ATTRIBUTES = 0x00000080
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004

PROCESS_TERMINATE = 0x0001
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                        wintypes.HANDLE]
CreateFileW.restype = ctypes.c_ssize_t

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [ctypes.c_ssize_t]
CloseHandle.restype = wintypes.BOOL

GetFileAttributesW = kernel32.GetFileAttributesW
GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
GetFileAttributesW.restype = wintypes.DWORD

SetFileAttributesW = kernel32.SetFileAttributesW
SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
SetFileAttributesW.restype = wintypes.BOOL

MoveFileExW = kernel32.MoveFileExW
MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
MoveFileExW.restype = wintypes.BOOL

DeleteFileW = kernel32.DeleteFileW
DeleteFileW.argtypes = [wintypes.LPCWSTR]
DeleteFileW.restype = wintypes.BOOL

RemoveDirectoryW = kernel32.RemoveDirectoryW
RemoveDirectoryW.argtypes = [wintypes.LPCWSTR]
RemoveDirectoryW.restype = wintypes.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = ctypes.c_ssize_t

TerminateProcess = kernel32.TerminateProcess
TerminateProcess.argtypes = [ctypes.c_ssize_t, wintypes.UINT]
TerminateProcess.restype = wintypes.BOOL

QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW
QueryFullProcessImageNameW.argtypes = [ctypes.c_ssize_t, wintypes.DWORD,
                                       wintypes.LPWSTR,
                                       ctypes.POINTER(wintypes.DWORD)]
QueryFullProcessImageNameW.restype = wintypes.BOOL

ERR_TEXT = {
    2: "找不到文件",
    3: "找不到路径",
    5: "拒绝访问",
    19: "介质写保护",
    32: "共享冲突(被占用)",
    33: "锁定冲突",
    123: "文件名或路径无效",
    145: "目录非空",
    183: "目标已存在",
    267: "目录无效",
    4390: "不是重解析点",
    1920: "无法访问该设备",
}


def err_text(code):
    return "%s(%d)" % (ERR_TEXT.get(code, "错误"), code)


# --------------------------------------------------------------------------
# 路径处理
# --------------------------------------------------------------------------
def lp(path):
    r"""转成 \\?\ 长路径形式，突破 260 字符限制。"""
    p = os.path.abspath(path)
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC" + p[1:]
    return "\\\\?\\" + p


def strip_prefix(p):
    if p.startswith("\\\\?\\UNC\\"):
        return "\\\\" + p[8:]
    if p.startswith("\\\\?\\"):
        return p[4:]
    return p


def canon(path):
    r"""安全判定用的规范形：剥 \\?\ 前缀、去尾空格/点/反斜杠、normpath、小写。

    \\?\ 前缀会让 GetFileAttributes / 路径比较全部失效，安全判断必须先剥掉，
    否则 '\\?\C:\' 这种写法能绕过盘符根目录拦截。
    """
    q = strip_prefix(os.path.abspath(path))
    q = q.rstrip(" .")
    q = os.path.normpath(q)
    q = strip_prefix(q)
    return q.lower().rstrip("\\")


def exists(path):
    return os.path.lexists(lp(path))


def get_attrs(path):
    v = GetFileAttributesW(lp(path))
    return None if v == INVALID_FILE_ATTRIBUTES else v


def is_reparse(path):
    a = get_attrs(path)
    return bool(a is not None and (a & FILE_ATTRIBUTE_REPARSE_POINT))


def entry_flags(entry):
    """复用 scandir 已缓存的属性，省掉每个 entry 一次 GetFileAttributes。

    返回 (attributes, is_link)；attributes 为 None 表示缓存里没有，调用方回退。
    """
    try:
        st = entry.stat(follow_symlinks=False)
    except OSError:
        return None, False
    attr = getattr(st, "st_file_attributes", 0)
    if not attr:
        return None, False
    return attr, bool(attr & FILE_ATTRIBUTE_REPARSE_POINT)


def clear_attrs(path):
    a = get_attrs(path)
    if a is None:
        return False
    if a & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM):
        new = FILE_ATTRIBUTE_NORMAL
        if a & FILE_ATTRIBUTE_DIRECTORY:
            new |= FILE_ATTRIBUTE_DIRECTORY
        return bool(SetFileAttributesW(lp(path), new))
    return True


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def win_delete_file(path):
    """直接调 Win32，绕开任何 Python 层的删除拦截。返回 (ok, code)。"""
    clear_attrs(path)
    if DeleteFileW(lp(path)):
        return True, 0
    return False, ctypes.get_last_error()


def win_remove_dir(path):
    clear_attrs(path)
    if RemoveDirectoryW(lp(path)):
        return True, 0
    return False, ctypes.get_last_error()


# --------------------------------------------------------------------------
# Restart Manager：查出谁占着目标
# --------------------------------------------------------------------------
class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD),
                ("ProcessStartTime", wintypes.FILETIME)]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [("Process", RM_UNIQUE_PROCESS),
                ("strAppName", wintypes.WCHAR * 256),
                ("strServiceShortName", wintypes.WCHAR * 64),
                ("ApplicationType", wintypes.DWORD),
                ("AppStatus", wintypes.ULONG),
                ("TSSessionId", wintypes.DWORD),
                ("bRestartable", wintypes.BOOL)]


ERROR_MORE_DATA = 234


def find_lockers(path):
    """返回 [(pid, 应用名)]，失败返回 []。"""
    try:
        rm = ctypes.WinDLL("RstrtMgr.dll", use_last_error=True)
    except OSError:
        return []
    rm.RmStartSession.argtypes = [ctypes.POINTER(wintypes.DWORD),
                                  wintypes.DWORD, wintypes.LPWSTR]
    rm.RmRegisterResources.argtypes = [wintypes.DWORD, wintypes.UINT,
                                       ctypes.POINTER(wintypes.LPCWSTR),
                                       wintypes.UINT,
                                       ctypes.POINTER(RM_UNIQUE_PROCESS),
                                       wintypes.UINT,
                                       ctypes.POINTER(wintypes.LPCWSTR)]
    rm.RmGetList.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.UINT),
                             ctypes.POINTER(wintypes.UINT),
                             ctypes.POINTER(RM_PROCESS_INFO),
                             ctypes.POINTER(wintypes.DWORD)]
    rm.RmEndSession.argtypes = [wintypes.DWORD]

    handle = wintypes.DWORD()
    key = ctypes.create_unicode_buffer(33)
    if rm.RmStartSession(ctypes.byref(handle), 0, key) != 0:
        return []
    try:
        names = (wintypes.LPCWSTR * 1)(lp(path))
        if rm.RmRegisterResources(handle, 1, names, 0, None, 0, None) != 0:
            return []
        need = wintypes.UINT(0)
        got = wintypes.UINT(0)
        reasons = wintypes.DWORD(0)
        rc = rm.RmGetList(handle, ctypes.byref(need), ctypes.byref(got), None,
                          ctypes.byref(reasons))
        if rc not in (0, ERROR_MORE_DATA) or need.value == 0:
            return []
        arr = (RM_PROCESS_INFO * need.value)()
        got = wintypes.UINT(need.value)
        rc = rm.RmGetList(handle, ctypes.byref(need), ctypes.byref(got), arr,
                          ctypes.byref(reasons))
        if rc != 0:
            return []
        out = []
        for i in range(got.value):
            info = arr[i]
            pid = int(info.Process.dwProcessId)
            name = (info.strAppName or "").strip()
            if not name:
                name = proc_name(pid)
            out.append((pid, name))
        return out
    except Exception:
        return []
    finally:
        try:
            rm.RmEndSession(handle)
        except Exception:
            pass


def proc_name(pid):
    """用 QueryFullProcessImageNameW 取名，不依赖系统语言和 tasklist 输出格式。"""
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return "?"
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        if QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value) or "?"
    except Exception:
        pass
    finally:
        CloseHandle(h)
    return "?"


PROTECTED_PROCS = {
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe",
    "dwm.exe", "fontdrvhost.exe", "memory compression", "registry",
}

SHELL_PROCS = {"explorer.exe"}

TERM_PROCS = {"cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe",
              "conhost.exe", "mintty.exe", "bash.exe", "wsl.exe", "code.exe"}


def kill_proc(pid, name):
    """结束进程。返回 (ok, 消息)。"""
    lower = (name or "").lower()
    if pid <= 4 or pid == os.getpid():
        return False, "受保护，跳过"
    if lower in PROTECTED_PROCS:
        return False, "系统关键进程，拒绝结束"
    h = OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        code = ctypes.get_last_error()
        if code == 5:
            return False, "权限不足(需管理员)"
        return False, "打不开进程(%d)" % code
    try:
        if TerminateProcess(h, 1):
            return True, "已结束"
        code = ctypes.get_last_error()
        if code == 5:
            return False, "权限不足(需管理员)"
        return False, "结束失败(%d)" % code
    finally:
        CloseHandle(h)


# --------------------------------------------------------------------------
# 谁把这个目录当成了工作目录
# --------------------------------------------------------------------------
# 目录被某进程设成 CWD 时，就算所有句柄都是共享模式、所有文件都删干净了，
# RemoveDirectoryW 照样返回 32（共享冲突）。Restart Manager 看不到这种占用，
# 只能自己进 PEB 把 RTL_USER_PROCESS_PARAMETERS.CurrentDirectory 读出来。
# 读的是当前位数布局，跨位数（32 位 Python 看 64 位进程）会读空，直接跳过。

_NtQueryInformationProcess = ctypes.WinDLL("ntdll").NtQueryInformationProcess
_NtQueryInformationProcess.argtypes = [ctypes.c_ssize_t, ctypes.c_uint,
                                       ctypes.c_void_p, ctypes.c_ulong,
                                       ctypes.POINTER(ctypes.c_ulong)]
_NtQueryInformationProcess.restype = ctypes.c_long

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_void_p,
                              ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

EnumProcesses = ctypes.WinDLL("psapi", use_last_error=True).EnumProcesses
EnumProcesses.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
                          ctypes.POINTER(wintypes.DWORD)]
EnumProcesses.restype = wintypes.BOOL

_PSIZE = ctypes.sizeof(ctypes.c_void_p)
_PEB_PARAMS_OFF = 0x10 if _PSIZE == 4 else 0x20     # PEB.ProcessParameters
_UPP_CURDIR_OFF = 0x24 if _PSIZE == 4 else 0x38     # RTL_USER_PROCESS_PARAMETERS.CurrentDirectory


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("Reserved1", ctypes.c_void_p),
                ("PebBaseAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2),
                ("UniqueProcessId", ctypes.c_void_p),
                ("Reserved3", ctypes.c_void_p)]


def _read_mem(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if not ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size,
                             ctypes.byref(got)):
        return None
    return buf.raw


def peb_cwd(pid):
    """读进程的当前工作目录。读不到（权限/位数/已退出）返回 None。"""
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                    False, pid)
    if not h:
        return None
    try:
        pbi = PROCESS_BASIC_INFORMATION()
        need = wintypes.ULONG(0)
        if _NtQueryInformationProcess(h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi),
                                      ctypes.byref(need)) != 0:
            return None
        if not pbi.PebBaseAddress:
            return None
        head = _read_mem(h, pbi.PebBaseAddress + _PEB_PARAMS_OFF, _PSIZE)
        if not head:
            return None
        params = int.from_bytes(head, "little")
        if not params:
            return None
        cur = _read_mem(h, params + _UPP_CURDIR_OFF, 8 + _PSIZE)
        if not cur:
            return None
        length = int.from_bytes(cur[0:2], "little")
        if length < 4 or length > 0x1000:
            return None
        buf = int.from_bytes(cur[8:8 + _PSIZE], "little")
        if not buf:
            return None
        raw = _read_mem(h, buf, length)
        if not raw:
            return None
        path = raw.decode("utf-16-le", "replace")
        # 位数猜错时读出来的是垃圾，只有长得像路径的才认
        if re.match(r"^[A-Za-z]:[\\/]", path) or path.startswith("\\\\"):
            return path
    except Exception:
        return None
    finally:
        CloseHandle(h)
    return None


_cwd_cache = {}
_cwd_cache_at = 0.0
_CWD_CACHE_TTL = 2.0


def invalidate_cwd_cache():
    global _cwd_cache_at
    _cwd_cache_at = 0.0


def _all_cwds():
    """扫一遍所有进程的工作目录，短时间缓存——一次运行里往往要问好几个目标。"""
    global _cwd_cache, _cwd_cache_at
    now = time.time()
    if _cwd_cache and now - _cwd_cache_at < _CWD_CACHE_TTL:
        return _cwd_cache
    found = {}
    buf = (wintypes.DWORD * 8192)()
    need = wintypes.DWORD(0)
    if EnumProcesses(buf, ctypes.sizeof(buf), ctypes.byref(need)):
        n = need.value // ctypes.sizeof(wintypes.DWORD)
        for i in range(n):
            pid = int(buf[i])
            if pid <= 4 or pid == os.getpid():
                continue
            cwd = peb_cwd(pid)
            if cwd:
                found[pid] = cwd
    _cwd_cache = found
    _cwd_cache_at = now
    return found


def find_cwd_holders(target):
    """返回 [(pid, 进程名, 工作目录)]：把 target 或它的子目录当成工作目录的进程。"""
    key = canon(target)
    if not key:
        return []
    out = []
    for pid, cwd in list(_all_cwds().items()):
        c = canon(cwd)
        if c == key or c.startswith(key + "\\"):
            out.append((pid, proc_name(pid), cwd))
    return out


# --------------------------------------------------------------------------
# 剪贴板：管理员窗口拖不进文件时靠它
# --------------------------------------------------------------------------
CF_HDROP = 15
CF_UNICODETEXT = 13

user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

user32.OpenClipboard.argtypes = [wintypes.HWND]
user32.OpenClipboard.restype = wintypes.BOOL
user32.CloseClipboard.argtypes = []
user32.CloseClipboard.restype = wintypes.BOOL
user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
user32.GetClipboardData.argtypes = [wintypes.UINT]
user32.GetClipboardData.restype = ctypes.c_ssize_t
shell32.DragQueryFileW.argtypes = [ctypes.c_ssize_t, wintypes.UINT,
                                   wintypes.LPWSTR, wintypes.UINT]
shell32.DragQueryFileW.restype = wintypes.UINT
kernel32.GlobalLock.argtypes = [ctypes.c_ssize_t]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalUnlock.argtypes = [ctypes.c_ssize_t]
kernel32.GlobalUnlock.restype = wintypes.BOOL


def _clip_open(attempts=10):
    """剪贴板同一时刻只给一个进程开，被别的程序占着就等一会儿。"""
    for _ in range(attempts):
        if user32.OpenClipboard(None):
            return True
        time.sleep(0.05)
    return False


def read_clipboard_paths():
    """剪贴板里的目标：优先「复制的文件」(CF_HDROP)，其次纯文本路径。"""
    if not _clip_open():
        return []
    try:
        if user32.IsClipboardFormatAvailable(CF_HDROP):
            h = user32.GetClipboardData(CF_HDROP)
            if h:
                n = int(shell32.DragQueryFileW(h, 0xFFFFFFFF, None, 0))
                out = []
                for i in range(n):
                    buf = ctypes.create_unicode_buffer(32768)
                    if shell32.DragQueryFileW(h, i, buf, 32768) and buf.value:
                        out.append(buf.value)
                if out:
                    return out
        if user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
            h = user32.GetClipboardData(CF_UNICODETEXT)
            if h:
                addr = kernel32.GlobalLock(h)
                if addr:
                    try:
                        text = ctypes.wstring_at(addr)
                    finally:
                        kernel32.GlobalUnlock(h)
                    if text and text.strip():
                        return [p for p in split_input(text.strip()) if p.strip()]
    except Exception:
        return []
    finally:
        user32.CloseClipboard()
    return []


# --------------------------------------------------------------------------
# 提权重开
# --------------------------------------------------------------------------
ShellExecuteW = ctypes.windll.shell32.ShellExecuteW
ShellExecuteW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                          wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int]
ShellExecuteW.restype = ctypes.c_ssize_t

ERROR_CANCELLED = 1223


def quote_args(items):
    return " ".join('"%s"' % x for x in items)


def relaunch_elevated(paths, extra=()):
    """用管理员权限重开一个窗口，把这些目标用命令行带过去。

    管理员窗口拖不进文件，所以路径必须自己传——这样用户不必再拖一次。
    返回 (ok, 说明)。
    """
    script = os.path.join(BASE_DIR, os.path.basename(__file__))
    params = quote_args([script] + list(paths) + list(extra))
    try:
        rc = int(ShellExecuteW(None, "runas", sys.executable, params, BASE_DIR, 1))
    except Exception:
        rc = -1
    if rc > 32:
        return True, ""
    if rc == ERROR_CANCELLED:
        return False, "在 UAC 弹窗里点了「否」"
    bat = os.path.join(BASE_DIR, "NukeIt.bat")
    if os.path.exists(bat):
        try:
            args = quote_args(list(paths) + list(extra))
            cmd = '/c ""%s" %s"' % (bat, args) if args else '/c "%s"' % bat
            rc = int(ShellExecuteW(None, "runas", "cmd.exe", cmd, BASE_DIR, 1))
            if rc > 32:
                return True, ""
            if rc == ERROR_CANCELLED:
                return False, "在 UAC 弹窗里点了「否」"
        except Exception:
            pass
    return False, "提权失败，可以手动右键 NukeIt.bat → 以管理员身份运行"


# --------------------------------------------------------------------------
# 删除内核
# --------------------------------------------------------------------------
def wait_gone(path, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if not exists(path):
            return True
        time.sleep(0.1)
    return not exists(path)


def dir_is_empty(path):
    try:
        with os.scandir(lp(path)) as it:
            for _ in it:
                return False
        return True
    except OSError:
        return False


def open_delete_on_close(path):
    """L2：以 DELETE 权限强开句柄并标记关闭时删除。返回 (ok, code)。"""
    clear_attrs(path)
    h = CreateFileW(lp(path),
                    DELETE | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_DELETE_ON_CLOSE,
                    None)
    if h == -1:
        return False, ctypes.get_last_error()
    CloseHandle(h)
    return True, 0


def add_pending_rename(path):
    key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                old, _ = winreg.QueryValueEx(key, "PendingFileRenameOperations")
            except FileNotFoundError:
                old = []
            if not isinstance(old, list):
                old = [old]
            entries = [x for x in old if x]
            entries.append("\\??\\" + os.path.abspath(path))
            entries.append("")
            winreg.SetValueEx(key, "PendingFileRenameOperations", 0,
                              winreg.REG_MULTI_SZ, entries)
        return True
    except Exception:
        return False


def schedule_reboot_delete(path):
    """L3：登记为重启时删除。"""
    try:
        if MoveFileExW(lp(path), None, MOVEFILE_DELAY_UNTIL_REBOOT):
            return True
    except Exception:
        pass
    return add_pending_rename(path)


# --------------------------------------------------------------------------
# 安全护栏
# --------------------------------------------------------------------------
SHELL_FOLDERS_KEY = (r"Software\Microsoft\Windows\CurrentVersion"
                     r"\Explorer\Shell Folders")


def shell_folder(name):
    """读注册表里的真实个人资料夹位置。

    桌面/文档/下载经常被重定向到别的盘（比如 D:\\Administrator\\Desktop），
    只按 %USERPROFILE%\\Desktop 判断会漏掉真实位置。
    """
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, SHELL_FOLDERS_KEY) as key:
            val, _ = winreg.QueryValueEx(key, name)
        if isinstance(val, str) and val.strip():
            return os.path.expandvars(val.strip())
    except Exception:
        pass
    return ""


def hard_guards():
    """精确匹配、永远不允许删除的目录。"""
    guards = {}
    home = os.path.expanduser("~")
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    prog = os.environ.get("ProgramFiles", r"C:\Program Files")
    prog86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    progdata = os.environ.get("ProgramData", r"C:\ProgramData")
    users = os.path.join(os.environ.get("SystemDrive", "C:"), "Users")
    plain = {
        sysroot: "Windows 系统目录",
        prog: "程序安装根目录",
        prog86: "程序安装根目录",
        progdata: "程序数据根目录",
        users: "用户目录",
        home: "当前用户主目录",
    }
    for name in ("Desktop", "Documents", "Downloads", "Pictures", "Music",
                 "Videos", "Favorites", "AppData", "OneDrive", "Saved Games"):
        plain[os.path.join(home, name)] = "个人资料根目录(%s)" % name
    redirected = {
        "Desktop": "桌面",
        "Personal": "我的文档",
        "My Pictures": "图片",
        "My Music": "音乐",
        "My Video": "视频",
        "{374DE290-123F-4565-9164-39C4925E467B}": "下载",
    }
    for key, label in redirected.items():
        real = shell_folder(key)
        if real:
            plain[real] = "个人资料根目录(%s，实际位置)" % label
    for k, v in plain.items():
        if k:
            guards[canon(k)] = v
    for d in "CDEFGHIJK":
        guards[d + ":\\$recycle.bin"] = "回收站"
        guards[d + ":\\system volume information"] = "系统卷信息"
    return guards


def hard_trees():
    """连整个子树都拒绝的目录（比 hard_guards 更严）。"""
    trees = {}
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    trees[canon(sysroot)] = "Windows 系统目录"
    prog = os.environ.get("ProgramFiles", r"C:\Program Files")
    trees[canon(os.path.join(prog, "WindowsApps"))] = "应用商店程序目录"
    return trees


# --------------------------------------------------------------------------
# 进度显示
# --------------------------------------------------------------------------
def fmt_int(n):
    try:
        return "{:,}".format(int(n))
    except Exception:
        return str(n)


def _cw(ch):
    """单个字符在控制台里占几列。中文/全角算 2 列，否则按 1 列。

    进度条要原地刷新，宽度算错就会留残影——中文路径很容易踩这个坑。
    """
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def disp_len(s):
    return sum(_cw(c) for c in s)


def cut_disp(s, limit):
    """按显示列宽截断，返回 (字符串, 实际宽度)。"""
    out = []
    w = 0
    for ch in s:
        cw = _cw(ch)
        if w + cw > limit:
            break
        out.append(ch)
        w += cw
    return "".join(out), w


def cut_tail(s, limit):
    """从尾部保留，用于显示路径末尾。"""
    out = []
    w = 0
    for ch in reversed(s):
        cw = _cw(ch)
        if w + cw > limit:
            break
        out.append(ch)
        w += cw
    return "".join(reversed(out))


class Progress(object):
    """单行原地刷新的进度条，只在真正的控制台里启用。

    小目标不画：几十个文件的活儿本来一闪就完，多画一行反而糊住输出。
    """

    def __init__(self, vt=False):
        try:
            is_tty = bool(sys.stdout.isatty())
        except Exception:
            is_tty = False
        self.enabled = is_tty
        self.vt = bool(vt)
        self.count = 0
        self.start = time.time()
        self.last = 0.0
        self.drawn = False
        self.min_count = 400
        try:
            cols = shutil.get_terminal_size((80, 20)).columns
        except Exception:
            cols = 80
        self.width = max(40, min(120, cols - 1))

    def begin(self, min_count=400):
        self.count = 0
        self.min_count = min_count
        self.start = time.time()
        self.last = 0.0

    def tick(self, n=1, tail=""):
        self.count += n
        if not self.enabled or self.count < self.min_count:
            return
        now = time.monotonic()
        if now - self.last < 0.1:
            return
        self.last = now
        el = max(0.05, time.time() - self.start)
        head = "    %s 项  %s/s  " % (fmt_int(self.count), fmt_int(self.count / el))
        tail = strip_prefix(tail or "")
        room = self.width - disp_len(head)
        if room > 8 and disp_len(tail) > room:
            tail = "…" + cut_tail(tail, room - 1)
        text, w = cut_disp(head + tail, self.width)
        try:
            if self.vt:
                sys.stdout.write("\r" + text + "\x1b[K")
            else:
                sys.stdout.write("\r" + text + " " * max(0, self.width - w))
            sys.stdout.flush()
            self.drawn = True
        except Exception:
            self.enabled = False

    def stop(self):
        if not self.drawn:
            return
        try:
            if self.vt:
                sys.stdout.write("\r\x1b[K")
            else:
                sys.stdout.write("\r" + " " * self.width + "\r")
            sys.stdout.flush()
        except Exception:
            pass
        self.drawn = False


# --------------------------------------------------------------------------
# 单个目标
# --------------------------------------------------------------------------
class Task(object):
    def __init__(self, raw, prog=None):
        self.raw = raw
        self.prog = prog
        self.idx = 0
        self.path = ""
        self.valid = False
        self.invalid_reason = ""
        self.kind = ""
        self.files = 0
        self.dirs = 0
        self.size = 0
        self.capped = False
        self.links = 0
        self.attr_text = "普通"
        self.is_link = False
        self.lockers = []
        self.cwd_pids = set()
        self.blocked = ""
        self.need_yes = False
        self.need_yes_reason = ""
        self.skip = False
        self.merged = False
        self.dry = False
        self.ok_files = 0
        self.ok_dirs = 0
        self.pending = 0
        self.reboot = 0
        self.failed = []
        self.stage_used = set()
        self.retry_left = RETRY_BUDGET
        self.cwd_probe_left = 3      # 运行期查「谁把它当工作目录」的次数上限
        self.run_status = ""

    # -- 体检 -------------------------------------------------------------
    def prepare(self):
        raw = self.raw
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
            raw = raw[1:-1]
        raw = os.path.expandvars(os.path.expanduser(raw))
        # 名字里可能真的带首尾空格（用 \\?\ 才能建出来），所以先按原样找，
        # 找不到再按去掉空白的样子找，最后才报不存在。
        cands = []
        for c in (raw, raw.strip(), raw.strip().strip('"')):
            if c and c not in cands:
                cands.append(c)
        if not cands:
            self.invalid_reason = "空路径"
            return
        picked = ""
        for c in cands:
            try:
                p = os.path.normpath(os.path.abspath(c))
            except Exception:
                continue
            if os.path.lexists(lp(p)):
                picked = p
                break
        if not picked:
            try:
                self.path = os.path.normpath(os.path.abspath(cands[0]))
            except Exception as exc:
                self.invalid_reason = "路径无效: %s" % exc
                return
            self.invalid_reason = "路径不存在"
            return
        path = picked
        self.path = path
        self.valid = True
        self.is_link = is_reparse(path)
        if self.is_link:
            self.kind = "链接(junction/符号链接)"
        elif os.path.isdir(lp(path)):
            self.kind = "文件夹"
        else:
            self.kind = "文件"

        # 先判危险路径：被拦截的目标不做全盘扫描，避免卡死
        self._check_danger()
        if self.blocked:
            return
        self._scan()
        self._describe_attrs()
        if not self.is_link:
            self.lockers = find_lockers(path)
            if os.path.isdir(lp(path)):
                # Restart Manager 只报打开的文件句柄，「被当成工作目录」它看不见，
                # 而这恰恰是空目录删不掉（32）最常见的原因，单独查一遍。
                for pid, name, _ in find_cwd_holders(path):
                    self.cwd_pids.add(pid)
                    if (pid, name) not in self.lockers:
                        self.lockers.append((pid, name))
        if self.size >= BIG_SIZE or self.files >= BIG_FILES:
            self._add_yes("目标很大（%s / %s 个文件）"
                          % (fmt_size(self.size), fmt_int(self.files)))

    def _add_yes(self, reason):
        if not self.need_yes:
            self.need_yes = True
            self.need_yes_reason = reason
        else:
            self.need_yes_reason += "；" + reason

    def _scan(self):
        if self.is_link:
            self.links = 1
            return
        if not os.path.isdir(lp(self.path)):
            try:
                self.size = os.path.getsize(lp(self.path))
            except OSError:
                self.size = 0
            self.files = 1
            return
        stack = [self.path]
        while stack:
            cur = stack.pop()
            try:
                with os.scandir(lp(cur)) as it:
                    for e in it:
                        if self.files >= SCAN_LIMIT:
                            self.capped = True
                            return
                        attr, is_link = entry_flags(e)
                        if attr is None:
                            attr = get_attrs(e.path) or 0
                            is_link = bool(attr & FILE_ATTRIBUTE_REPARSE_POINT)
                        if is_link:
                            self.links += 1
                            continue
                        if attr & FILE_ATTRIBUTE_DIRECTORY:
                            self.dirs += 1
                            stack.append(e.path)
                        else:
                            self.files += 1
                            try:
                                self.size += e.stat(follow_symlinks=False).st_size
                            except OSError:
                                pass
                            if self.prog:
                                self.prog.tick(1, e.path)
            except OSError:
                pass

    def _describe_attrs(self):
        a = get_attrs(self.path)
        if a is None:
            return
        tags = []
        if a & FILE_ATTRIBUTE_READONLY:
            tags.append("只读")
        if a & FILE_ATTRIBUTE_HIDDEN:
            tags.append("隐藏")
        if a & FILE_ATTRIBUTE_SYSTEM:
            tags.append("系统")
        if tags:
            self.attr_text = "+".join(tags)

    def _check_danger(self):
        key = canon(self.path)

        # 盘符根目录：注意用 canon 之后的形态判断，挡住 \\?\C:\ 和 "C:\ " 这类写法
        if re.match(r"^[a-z]:$", key):
            self.blocked = "这是盘符根目录"
            return

        guards = hard_guards()
        if key in guards:
            self.blocked = "这是系统目录或个人资料根目录（%s）" % guards[key]
            return

        for g, label in hard_trees().items():
            if key == g or key.startswith(g + "\\"):
                self.blocked = "位于受保护目录 %s 之内，拒绝删除" % label
                return

        tool = canon(BASE_DIR)
        if key == tool or tool.startswith(key + "\\"):
            self.blocked = "这是 NukeIt 自身所在目录或其上级"
            return
        try:
            cwd = canon(os.getcwd())
            if key == cwd or cwd.startswith(key + "\\"):
                self.blocked = "这是当前工作目录"
                return
        except OSError:
            pass

        parts = [x for x in key.split("\\") if x]
        if len(parts) - 1 <= 2:
            self._add_yes("路径层级过浅（%s）" % self.path)

    # -- 执行 -------------------------------------------------------------
    def run(self):
        if self.is_link:
            self._del_link_counted(self.path)
        elif os.path.isdir(lp(self.path)):
            self._walk_tree(self.path)
        else:
            self._remove_file(self.path)
        return self.status()

    def _tick(self, path):
        if self.prog:
            self.prog.tick(1, path)

    def _fail(self, path, reason):
        # scandir 走的是 \\?\ 形式，报给用户前把前缀剥掉，不然一行里全是噪音
        self.failed.append((strip_prefix(path), reason))

    def _del_link(self, path):
        """只删链接本身，绝不进入目标目录。返回 (状态, 错误码)。"""
        for fn in (win_remove_dir, win_delete_file):
            ok, code = fn(path)
            if ok:
                return "ok", 0
        good, code = open_delete_on_close(path)
        if good:
            return ("ok" if wait_gone(path, 1.5) else "pending"), 0
        if schedule_reboot_delete(path):
            return "reboot", 0
        return "fail", code

    def _del_link_counted(self, path):
        state, code = self._del_link(path)
        if state == "ok":
            self.ok_files += 1
        elif state == "pending":
            self.pending += 1
            self.stage_used.add("L2")
        elif state == "reboot":
            self.reboot += 1
            self.stage_used.add("L3")
        else:
            self._fail(path, err_text(code))
        self._tick(path)

    def _walk_tree(self, root):
        """广度优先收集目录，边扫边删文件；最后按逆序删目录（子目录先于父目录）。

        改成显式栈是因为深目录递归会把解释器栈打穿，那属于直接崩溃而不是抛异常。
        """
        dirs = [root]
        i = 0
        while i < len(dirs):
            cur = dirs[i]
            i += 1
            try:
                with os.scandir(lp(cur)) as it:
                    entries = list(it)
            except OSError as exc:
                self._fail(cur, "无法读取: " + err_text(
                    getattr(exc, "winerror", 0) or 5))
                continue
            for e in entries:
                child = e.path
                try:
                    attr, is_link = entry_flags(e)
                    if attr is None:
                        attr = get_attrs(child) or 0
                        is_link = bool(attr & FILE_ATTRIBUTE_REPARSE_POINT)
                except OSError:
                    self._fail(child, "无法读取属性")
                    continue
                if is_link:
                    self._del_link_counted(child)
                elif attr & FILE_ATTRIBUTE_DIRECTORY:
                    dirs.append(child)
                else:
                    self._remove_file(child)
        for d in reversed(dirs):
            self._remove_dir(d)

    def _try_l1(self, fn, path, attempts=3, delay=0.3):
        """L1 删除；共享冲突先重试——瞬时占用（索引/缩略图扫描）等一会就过。

        retry_left 是全局预算，避免上万个文件被占用时每项都等 1 秒，看起来像卡死。
        """
        ok, code = fn(path)
        tries = 1
        while not ok and code == 32 and tries < attempts and self.retry_left > 0:
            self.retry_left -= 1
            time.sleep(delay)
            ok, code = fn(path)
            tries += 1
        return ok, code

    def _remove_file(self, path):
        ok, code = self._try_l1(win_delete_file, path)
        if ok:
            self.ok_files += 1
            self.stage_used.add("L1")
            self._tick(path)
            return
        good, l2code = open_delete_on_close(path)
        if good:
            self.stage_used.add("L2")
            if wait_gone(path, 1.2):
                self.ok_files += 1
            else:
                self.pending += 1
            self._tick(path)
            return
        if schedule_reboot_delete(path):
            self.reboot += 1
            self.stage_used.add("L3")
            self._tick(path)
            return
        self._fail(path, err_text(l2code or code))
        self._tick(path)

    def _blame_cwd(self, path):
        """查是谁把这个目录当工作目录，顺手记进 lockers 供后面结束进程。"""
        if self.cwd_probe_left <= 0:
            return ""
        self.cwd_probe_left -= 1
        holders = find_cwd_holders(path)
        if not holders:
            return ""
        names = []
        for pid, name, _ in holders:
            self.cwd_pids.add(pid)
            if (pid, name) not in self.lockers:
                self.lockers.append((pid, name))
            names.append("%s(PID %d)" % (name, pid))
        return "被 %s 当作工作目录" % "、".join(names)

    def _remove_dir(self, path):
        ok, code = self._try_l1(win_remove_dir, path, attempts=4, delay=0.35)
        if ok:
            self.ok_dirs += 1
            self.stage_used.add("L1")
            self._tick(path)
            return
        if code == 145:
            # 目录非空 = 里面的东西没删掉。若子项已经排队重启删除，父目录得一起排，
            # 否则开机后只会剩一堆空壳目录。
            if self.reboot and schedule_reboot_delete(path):
                self.reboot += 1
                self.stage_used.add("L3")
            else:
                self._fail(path, "目录非空：内部仍有删不掉的项")
            self._tick(path)
            return

        good, l2code = open_delete_on_close(path)
        if good:
            self.stage_used.add("L2")
            if wait_gone(path, 1.2):
                self.ok_dirs += 1
            elif dir_is_empty(path):
                self.pending += 1        # 空的，只等句柄释放
            else:
                # 非空目录就算句柄拿到了也删不掉，别报成「待释放」骗自己
                self._fail(path, "目录非空：内部仍有删不掉的项")
            self._tick(path)
            return

        if schedule_reboot_delete(path):
            self.reboot += 1
            self.stage_used.add("L3")
            self._tick(path)
            return

        why = ""
        if l2code in (32, 5):
            why = self._blame_cwd(path)
        msg = err_text(l2code or code)
        if why:
            msg += "，" + why + "（结束它就能删）"
        elif l2code == 32:
            msg += "，多半是某程序把它当工作目录或开着窗口"
        if not is_admin():
            msg += "；重启删除也要管理员权限"
        self._fail(path, msg)
        self._tick(path)

    def status(self):
        done = self.ok_files + self.ok_dirs
        if self.failed:
            return "partial" if done else "fail"
        if self.pending or self.reboot:
            return "deferred"
        return "ok"

    def retry_failed(self):
        """只重试失败清单里的路径（结束占用进程后调用）。返回挽回的条目数。"""
        if self.dry or not self.failed:
            return 0
        old = self.failed
        self.failed = []
        for path, _ in old:
            if not exists(path):
                self.ok_files += 1
                continue
            if is_reparse(path):
                self._del_link_counted(path)
            elif os.path.isdir(lp(path)):
                self._remove_dir(path)
            else:
                self._remove_file(path)
        return len(old) - len(self.failed)


# --------------------------------------------------------------------------
# 界面
# --------------------------------------------------------------------------
class IO(object):
    def __init__(self):
        self.color = self._enable_vt()

    @staticmethod
    def _enable_vt():
        if not sys.stdout.isatty():
            return False
        try:
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)
                return True
        except Exception:
            pass
        return False

    def _w(self, code, s):
        if not self.color:
            return s
        return "\x1b[%sm%s\x1b[0m" % (code, s)

    def red(self, s):
        return self._w("91", s)

    def grn(self, s):
        return self._w("92", s)

    def yel(self, s):
        return self._w("93", s)

    def dim(self, s):
        return self._w("90", s)

    def bold(self, s):
        return self._w("1", s)

    def line(self, ch="=", n=62):
        print(ch * n)

    def banner(self):
        self.line("=")
        print("  %s %s   ·   Windows 强制删除工具" % (APP_NAME, VERSION))
        print(self.dim("  三级降级：常规 → 强开句柄 → 重启时删除"))
        self.line("=")
        print("")

    def read_paths(self):
        # 只读一行：拖多个进来是往同一行里追加的，按一次回车就够
        print("把文件或文件夹拖进本窗口（可连续拖多个），拖完按回车。")
        print(self.dim("  管理员窗口拖不进来是 Windows 的限制：资源管理器里选中目标按"))
        print(self.dim("  Ctrl+C 复制，回到这里直接按回车，我从剪贴板取；粘贴路径也行。"))
        for _ in range(3):
            try:
                line = input(self.bold("> "))
            except (EOFError, KeyboardInterrupt):
                print("")
                return []
            if line.strip():
                if line.strip().lower() in ("q", "quit", "exit"):
                    return []
                return [p for p in split_input(line) if p.strip()]
            got = read_clipboard_paths()
            if got:
                print(self.dim("  剪贴板里 %d 项：" % len(got)))
                for g in got[:12]:
                    print(self.dim("    " + g))
                if len(got) > 12:
                    print(self.dim("    … 共 %s 项" % fmt_int(len(got))))
                return got
            print(self.yel("  剪贴板里没有文件。先选中目标按 Ctrl+C，再回来按回车；"
                           "输入 q 退出。"))
        print("没拿到任何目标，退出。")
        return []

    def show(self, t):
        print(self.bold("[%d] %s" % (t.idx, t.path or t.raw)))
        if not t.valid:
            print("    %s" % self.red("无效：" + t.invalid_reason))
            return
        if t.blocked:
            print("    %s" % self.red("拒绝删除：" + t.blocked))
            return
        print("    类型      %s" % t.kind)
        if t.is_link:
            print("    内容      %s" % "1 个链接项（只删链接本身，不进入目标）")
        else:
            cnt = "%s 个文件, %s 个文件夹, %s" % (fmt_int(t.files), fmt_int(t.dirs),
                                                 fmt_size(t.size))
            if t.links:
                cnt += "（另有 %s 个链接项，只删链接）" % fmt_int(t.links)
            if t.capped:
                cnt += " …统计已截断"
            print("    内容      %s" % cnt)
        print("    属性      %s" % t.attr_text)
        if t.lockers:
            names = ", ".join("%s (PID %d)%s" % (
                n, p, self.dim(" ←工作目录") if p in t.cwd_pids else "")
                for p, n in t.lockers)
            print("    占用      %s" % self.yel(names))
        else:
            print("    占用      %s" % self.dim("未检测到"))
        if t.merged:
            print("    备注      %s" % self.dim("已包含在上面的目标里，不重复处理"))

    def confirm(self, tasks, all_indices=None):
        print("")
        self.line("-")
        tot_f = sum(t.files for t in tasks)
        tot_d = sum(t.dirs for t in tasks)
        tot_s = sum(t.size for t in tasks)
        print("共 %d 项 | %s 个文件 %s 个文件夹 | %s"
              % (len(tasks), fmt_int(tot_f), fmt_int(tot_d), fmt_size(tot_s)))
        print(self.red("删除不进回收站，无法恢复。"))
        print("回车 = 全部删除    输入 n = 取消    输入编号跳过该项（如 1,3）")
        indices = all_indices or set(t.idx for t in tasks)
        for _ in range(3):
            try:
                ans = input(self.bold("确认 > "))
            except (EOFError, KeyboardInterrupt):
                return None
            kind, nums = parse_confirm(ans, indices)
            if kind == "all":
                return tasks
            if kind == "cancel":
                return None
            if kind == "skip":
                for t in tasks:
                    if t.idx in nums:
                        t.skip = True
                return tasks
            print(self.red("没看懂这个输入，什么都没做。回车=全删，n=取消，"
                           "或输入要跳过的编号，如 1,3"))
        print(self.red("连续 3 次无法识别，按取消处理。"))
        return None

    def ask_yes(self, reason):
        print("")
        print(self.red("[!] 危险目标，二次确认："))
        for line in reason.split("\n"):
            print("      %s" % line)
        try:
            ans = input(self.red("输入大写 YES 继续：")).strip()
        except (EOFError, KeyboardInterrupt):
            return False
        return ans == "YES"

    def ask_kill(self, pairs, note="以下进程正占用目标"):
        print("")
        print(self.yel("[!] %s：" % note))
        for pid, name in pairs:
            tag = ""
            lower = (name or "").lower()
            if lower in SHELL_PROCS:
                tag = self.dim("  ← 桌面会短暂刷新")
            elif lower in TERM_PROCS:
                tag = self.dim("  ← 终端/编辑器，关掉那个窗口更稳")
            print("      %s (PID %d)%s" % (name, pid, tag))
        print(self.dim("      结束进程会丢失该程序里没保存的内容，请先确认。"))
        try:
            ans = input("结束这些进程后继续删除？(y/N) ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("")
            return False
        return ans in ("y", "yes")


def parse_confirm(ans, indices):
    """解析确认输入。返回 (kind, nums)：

    all     —— 全部删除（空输入）
    cancel  —— 取消
    skip    —— 只删这些编号以外的
    invalid —— 看不懂，调用方应当重新问，绝不能当成「全删」
    """
    s = (ans or "").strip()
    if s == "":
        return "all", set()
    if s.lower() in ("n", "no", "q", "quit", "c", "cancel"):
        return "cancel", set()
    nums = set()
    for part in re.split(r"[,，、\s]+", s):
        if not part:
            continue
        if not part.isdigit():
            return "invalid", set()
        v = int(part)
        if v not in indices:
            return "invalid", set()
        nums.add(v)
    if not nums:
        return "invalid", set()
    return "skip", nums


def split_input(line):
    """把一行拖入的文本拆成多个路径。

    Windows 拖多个进来时每项都会被引号包起来，形如：
        "C:\\a b\\x.txt" "D:\\临时\\y" "C:\\带,逗&符的目录"
    但单项、手动粘贴时可能没有引号，所以规则是：
      1. 有引号的段按原样取出（空格、逗号、&、^ 都不动）；
      2. 引号外剩下的部分，先整体当一条路径试，不行再按空白拆开逐条试；
      3. 实在认不出就原样留着，交给后面报「路径不存在」。
    """
    if not line or not line.strip():
        return []
    items = []
    rest = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == '"':
            j = line.find('"', i + 1)
            if j < 0:
                rest.append(line[i:])
                break
            seg = line[i + 1:j]
            if seg.strip():
                items.append(seg)
            i = j + 1
            continue
        rest.append(ch)
        i += 1

    tail = "".join(rest).strip()
    if tail:
        if os.path.lexists(lp(tail)):
            items.append(tail)
        else:
            parts = [p for p in re.split(r"\s+", tail) if p]
            found = [p for p in parts if os.path.lexists(lp(p))]
            if len(found) == len(parts) and len(parts) > 1:
                items.extend(parts)
            elif found:
                items.extend(found)
            else:
                items.append(tail)
    return items


def prune_nested(tasks):
    """去掉被上级目标包含的条目（拖了文件夹又顺带拖了里面的文件）。

    只对能删的目标做，避免上级被拦下时把下级也一起丢掉。
    """
    keys = [canon(t.path) for t in tasks]
    exact = [os.path.normcase(os.path.normpath(t.path)) for t in tasks]
    keep = []
    seen = set()
    for i, t in enumerate(tasks):
        if exact[i] in seen:
            continue
        nested = False
        for j in range(len(tasks)):
            if i == j or not keys[j]:
                continue
            if keys[i].startswith(keys[j] + "\\"):
                nested = True
                break
        if not nested:
            keep.append(t)
            seen.add(exact[i])
    return keep


def fmt_size(n):
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            if unit == "B":
                return "%d B" % int(v)
            return "%.2f %s" % (v, unit)
        v /= 1024.0


STATUS_TEXT = {
    "ok": ("成功", "grn"),
    "partial": ("部分成功", "yel"),
    "deferred": ("已投递删除(等占用释放)", "yel"),
    "fail": ("失败", "red"),
    "blocked": ("已拦截", "red"),
    "invalid": ("无效", "red"),
    "skipped": ("已跳过", "dim"),
    "merged": ("已合并", "dim"),
    "dry": ("仅预览(未删除)", "dim"),
}


USAGE = """用法: nuke.py [路径 ...] [选项]

  默认：拖进来、回车，直接删。删不掉的会报出占用程序再问你要不要结束。
  一次可以拖多个，也可以分几行拖；带空格、逗号、& 的名字都认。

      --ask        先列清单并等一次确认再删（默认不等）
      --dry-run    只体检和预览，不真删
      --no-kill    不结束占用进程
      --hold       结束时停住等回车（提权重开时自动带上，防止窗口一闪就没）
  -y, --yes        全自动：不等确认，也不结束进程（脚本用）
  -h, --help       显示帮助
  -v, --version    显示版本"""


def parse_args(argv):
    opts = {"paths": [], "yes": False, "dry": False, "no_kill": False,
            "ask": False, "hold": False, "help": False, "version": False}
    only_paths = False
    for a in argv:
        low = a.lower()
        if only_paths:
            opts["paths"].append(a)
        elif a == "--":
            only_paths = True
        elif low in ("-y", "--yes"):
            opts["yes"] = True
        elif low == "--ask":
            opts["ask"] = True
        elif low == "--dry-run":
            opts["dry"] = True
        elif low == "--no-kill":
            opts["no_kill"] = True
        elif low == "--hold":
            opts["hold"] = True
        elif low in ("-h", "--help"):
            opts["help"] = True
        elif low in ("-v", "--version"):
            opts["version"] = True
        else:
            opts["paths"].append(a)
    return opts


def collect_probe_paths(tasks, limit=12):
    out = []
    for t in tasks:
        for p, _ in t.failed:
            if len(out) >= limit:
                return out
            if p not in out:
                out.append(p)
    return out


def uniq_pairs(pairs):
    seen = set()
    out = []
    for pid, name in pairs:
        if pid in seen or pid == os.getpid() or pid <= 4:
            continue
        seen.add(pid)
        out.append((pid, name))
    return out


def main():
    opts = parse_args(sys.argv[1:])
    if opts["version"]:
        print("%s %s" % (APP_NAME, VERSION))
        return 0
    if opts["help"]:
        print(USAGE)
        return 0

    io = IO()
    io.banner()

    paths = opts["paths"]
    if not paths:
        paths = io.read_paths()
    paths = [p for p in paths if p.strip()]
    if not paths:
        print("没有输入任何路径，退出。")
        return 0

    prog = Progress(io.color)
    tasks = []
    for raw in paths:
        t = Task(raw, prog)
        prog.begin()
        t.prepare()
        prog.stop()
        tasks.append(t)

    # 拖了文件夹又顺带拖了里面的东西时，只保留上级，避免重复处理
    alive = [t for t in tasks if t.valid and not t.blocked]
    keep_ids = set(id(t) for t in prune_nested(alive))
    for t in alive:
        if id(t) not in keep_ids:
            t.merged = True

    print("")
    for i, t in enumerate(tasks, 1):
        t.idx = i
        io.show(t)

    usable = []
    for t in tasks:
        if not t.valid:
            t.run_status = "invalid"
        elif t.blocked:
            t.run_status = "blocked"
        elif t.merged:
            t.run_status = "merged"
        else:
            usable.append(t)

    if not usable:
        print("")
        io.line("-")
        print(io.red("没有可删除的目标，退出。"))
        io.line("-")
        return 1

    if opts["ask"] and not opts["yes"]:
        picked = io.confirm(usable, set(range(1, len(tasks) + 1)))
        if picked is None:
            print("已取消，未删除任何内容。")
            return 0

    risky = [t for t in usable if t.need_yes and not t.skip]
    if risky and not opts["yes"]:
        reason = "\n".join("%s  (%s)" % (t.path, t.need_yes_reason) for t in risky)
        if not io.ask_yes(reason):
            print("未通过二次确认，已退出。")
            return 0

    # 占用进程：放在确认之后，避免结束进程后又被取消
    if not opts["no_kill"] and not opts["dry"] and not opts["yes"]:
        pairs = []
        for t in usable:
            if not t.skip:
                pairs.extend(t.lockers)
        uniq = uniq_pairs(pairs)
        if uniq and io.ask_kill(uniq):
            print("")
            for pid, name in uniq:
                ok, msg = kill_proc(pid, name)
                mark = io.grn("OK") if ok else io.red("NG")
                print("    [%s] %s (PID %d) — %s" % (mark, name, pid, msg))
            time.sleep(0.4)
            invalidate_cwd_cache()
            for t in usable:
                t.lockers = find_lockers(t.path)
            print("")

    print("")
    io.line("-")
    ran = []
    for t in usable:
        if t.skip:
            t.run_status = "skipped"
            print("[%d] %s" % (t.idx, io.dim("跳过")))
            continue
        t.dry = opts["dry"]
        name = os.path.basename(t.path.rstrip("\\")) or t.path
        print("[%d] %s %s" % (t.idx, "预览" if opts["dry"] else "删除中 …", name))
        prog.begin()
        try:
            t.run_status = "dry" if opts["dry"] else t.run()
        except KeyboardInterrupt:
            prog.stop()
            print("")
            print(io.yel("已中断，后续目标未处理。"))
            t.run_status = t.status()
            ran.append(t)
            for rest in usable:
                if rest is not t and not rest.skip and not rest.run_status:
                    rest.run_status = "skipped"
            break
        prog.stop()
        ran.append(t)
        text, color = STATUS_TEXT.get(t.run_status, ("未知", "dim"))
        stages = "".join(sorted(t.stage_used))
        detail = []
        if t.ok_files:
            detail.append("%s 文件" % fmt_int(t.ok_files))
        if t.ok_dirs:
            detail.append("%s 目录" % fmt_int(t.ok_dirs))
        if t.pending:
            detail.append("待释放 %s" % fmt_int(t.pending))
        if t.reboot:
            detail.append("待重启 %s" % fmt_int(t.reboot))
        if stages:
            detail.append("手段 " + stages)
        tail = ("（" + " · ".join(detail) + "）") if detail else ""
        print("    %s %s" % (getattr(io, color)(text), io.dim(tail)))
        for fp, reason in t.failed[:6]:
            print("      %s %s" % (io.dim("·"), io.dim("%s  [%s]" % (fp, reason))))
        if len(t.failed) > 6:
            print("      %s" % io.dim("… 另有 %s 项没删掉"
                                     % fmt_int(len(t.failed) - 6)))

    # 第二轮：删不掉的反查占用者，结束进程后只重试失败项
    failed_tasks = [t for t in ran if t.failed and not opts["dry"]]
    if failed_tasks and not opts["no_kill"] and not opts["yes"]:
        pairs = []
        for p in collect_probe_paths(failed_tasks):
            pairs.extend(find_lockers(p))
            if os.path.isdir(lp(p)):
                # 目录的 32 十有八九是工作目录被占，RM 查不出来，自己查
                pairs.extend((pid, name) for pid, name, _
                             in find_cwd_holders(p))
        uniq = uniq_pairs(pairs)
        if uniq and io.ask_kill(uniq, "以下进程占着删不掉的目标"):
            print("")
            for pid, name in uniq:
                ok, msg = kill_proc(pid, name)
                mark = io.grn("OK") if ok else io.red("NG")
                print("    [%s] %s (PID %d) — %s" % (mark, name, pid, msg))
            time.sleep(0.5)
            invalidate_cwd_cache()
            print("")
            for t in failed_tasks:
                before = len(t.failed)
                rec = t.retry_failed()
                t.run_status = t.status()
                if rec:
                    print("    [%d] %s 重试挽回 %s 项，剩余失败 %s 项"
                          % (t.idx, io.grn("✓"), fmt_int(rec),
                             fmt_int(len(t.failed))))
                else:
                    print("    [%d] %s 重试无变化（%s → %s 项）"
                          % (t.idx, io.dim("·"), fmt_int(before),
                             fmt_int(len(t.failed))))

    # 汇总
    counts = {}
    for t in tasks:
        key = t.run_status or ("blocked" if t.blocked else
                               ("invalid" if not t.valid else "unknown"))
        counts[key] = counts.get(key, 0) + 1
    print("")
    io.line("=")
    summary = []
    for key, label in (("ok", "成功"), ("deferred", "待释放/待重启"),
                       ("partial", "部分成功"), ("fail", "失败"),
                       ("blocked", "拦截"), ("invalid", "无效"),
                       ("merged", "合并"), ("skipped", "跳过"),
                       ("dry", "预览")):
        if counts.get(key):
            summary.append("%s %d" % (label, counts[key]))
    print("  " + "  ·  ".join(summary))
    left = [t for t in ran if t.failed and not opts["dry"]]
    if left and not is_admin() and not opts["yes"]:
        print(io.yel("  还没删掉的，要么占用进程没结束，要么得靠管理员权限（写重启删除"))
        print(io.yel("  队列、动别人的进程和目录）。提权重开会把这几项目标用命令行带过去。"))
    io.line("=")

    # 提权重试：管理员窗口拖不进文件，所以路径必须随命令行传过去
    if left and not is_admin() and not opts["yes"]:
        print("")
        try:
            ans = input(io.bold("用管理员权限重开窗口、只重试这 %d 项？(Y/n) "
                                % len(left))).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans in ("", "y", "yes"):
            ok, why = relaunch_elevated([t.path for t in left], ["--hold"])
            if ok:
                print("  已用管理员权限重开，本窗口不再处理。")
                return 1
            print(io.red("  " + why))
            print(io.dim("  也可以右键 NukeIt.bat → 以管理员身份运行，然后在资源管理器"))
            print(io.dim("  里选中目标 Ctrl+C，回到新窗口直接回车从剪贴板取。"))

    return 0 if not (counts.get("fail") or counts.get("partial")) else 1


if __name__ == "__main__":
    # --hold 放在最外面：提权重开的新窗口必须停住，否则结果一闪就没了
    _hold = "--hold" in [a.lower() for a in sys.argv[1:]]
    try:
        _rc = main()
    except KeyboardInterrupt:
        print("\n已中断。")
        _rc = 130
    if _hold:
        try:
            input("\n按回车关闭窗口 …")
        except (EOFError, KeyboardInterrupt):
            pass
    sys.exit(_rc)

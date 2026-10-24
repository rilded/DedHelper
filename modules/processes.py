"""
Модуль управления процессами Windows
Расширенный диспетчер задач с заморозкой процессов, снятием флага
"критический" и эвристикой поиска подозрительных критических процессов.

Методы взяты из SimpleUnlocker (TMCore.cs), плюс:
  - проверка подписи Microsoft (WinVerifyTrust)
  - проверка "критичности" процесса (NtQueryInformationProcess / BreakOnTermination)
  - безопасное завершение критического процесса (suspend -> unmark -> kill)
  - поиск подозрительных критических процессов БЕЗ списка имён

Изменения v7.0:
  - Убран дублирующий (и ошибочный) блок `def is_critical_process` /
    `def is_process_suspicious` внутри ProcessManager — оставлены
    вызовы модульных функций. Логика не менялась.
"""

import ctypes
from ctypes import wintypes
import subprocess
import logging
import os
import hashlib

# Константа для скрытия окна консоли
CREATE_NO_WINDOW = 0x08000000

# Константы для работы с процессами
PROCESS_TERMINATE = 0x0001
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_SET_INFORMATION = 0x0200
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_DUP_HANDLE = 0x0040
PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Приоритеты процессов
IDLE_PRIORITY_CLASS = 0x00000040
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
NORMAL_PRIORITY_CLASS = 0x00000020
ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
HIGH_PRIORITY_CLASS = 0x00000080
REALTIME_PRIORITY_CLASS = 0x00000100

# Настройка логирования
logger = logging.getLogger(__name__)

# ntdll
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

# Прототипы (важно для x64: HANDLE != int32!)
_kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
_kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_kernel32.OpenProcess.restype = wintypes.HANDLE
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE

ntdll.NtQueryInformationProcess.argtypes = [
    wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p,
    wintypes.ULONG, ctypes.POINTER(wintypes.ULONG),
]
ntdll.NtQueryInformationProcess.restype = ctypes.c_long

ntdll.NtSetInformationProcess.argtypes = [
    wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG,
]
ntdll.NtSetInformationProcess.restype = ctypes.c_long

ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
ntdll.NtSuspendProcess.restype = ctypes.c_long
ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
ntdll.NtResumeProcess.restype = ctypes.c_long

ProcessBreakOnTermination = 29  # 0x1D

# ---------------------------------------------------------------------------
# Перечисление процессов через CreateToolhelp32Snapshot.
# ---------------------------------------------------------------------------
TH32CS_SNAPPROCESS = 0x00000002


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def _toolhelp_snapshot():
    """[(pid, имя, pid родителя), ...] — работает без WMI/tasklist."""
    out = []
    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == -1:
        return out
    try:
        pe = _PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            out.append((int(pe.th32ProcessID), pe.szExeFile,
                       int(pe.th32ParentProcessID)))
            ok = k32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        k32.CloseHandle(snap)
    return out


def get_process_path(pid: int) -> str:
    """Полный путь к exe процесса по WinAPI (без WMI)."""
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return ""
    finally:
        k32.CloseHandle(h)


def generate_random_name(length: int = 8) -> str:
    import random
    import string
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def run_hidden_command(cmd: str, capture_output: bool = False) -> subprocess.CompletedProcess:
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return subprocess.run(
        cmd, shell=True, capture_output=capture_output,
        startupinfo=startupinfo, creationflags=CREATE_NO_WINDOW,
    )


def run_hidden_powershell(ps_command: str, capture_output: bool = True, random_name: bool = True) -> subprocess.CompletedProcess:
    import tempfile
    import shutil
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    if random_name:
        temp_dir = tempfile.mkdtemp(prefix='PS_')
        ps_exe = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                              'System32\\WindowsPowerShell\\v1.0\\powershell.exe')
        ps_copy = os.path.join(temp_dir, generate_random_name(12) + '.exe')
        try:
            shutil.copy2(ps_exe, ps_copy)
        except Exception as e:
            logger.error(f"Не удалось создать копию PowerShell: {e}")
            ps_copy = ps_exe
        return subprocess.run(
            [ps_copy, '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
            capture_output=capture_output, startupinfo=startupinfo,
            creationflags=CREATE_NO_WINDOW,
        )
    return subprocess.run(
        ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
        capture_output=capture_output, startupinfo=startupinfo,
        creationflags=CREATE_NO_WINDOW,
    )


def decode_output(stdout_bytes: bytes) -> str:
    if not stdout_bytes:
        return ""
    for encoding in ['utf-8', 'cp1251', 'cp866']:
        try:
            return stdout_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return stdout_bytes.decode('utf-8', errors='replace')


# ---------------------------------------------------------------------------
# Системный путь и подпись Microsoft — БЕЗ списка имён процессов.
# ---------------------------------------------------------------------------

_SYSTEM_ROOT = os.path.normcase(
    os.environ.get('SystemRoot', r'C:\Windows')
).rstrip('\\')


def is_system_path(path: str) -> bool:
    """Путь внутри %SystemRoot% (C:\\Windows\\...)."""
    if not path:
        return False
    try:
        p = os.path.normcase(os.path.abspath(path))
    except Exception:
        return False
    return p == _SYSTEM_ROOT or p.startswith(_SYSTEM_ROOT + os.sep)


# --- WinVerifyTrust ---
class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.POINTER(_GUID))]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_PROV_FLAGS_CACHE_ONLY = 0x1000

_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)

try:
    _wintrust = ctypes.WinDLL('wintrust', use_last_error=True)
    _wintrust.WinVerifyTrust.argtypes = [
        wintypes.HWND, ctypes.POINTER(_GUID), ctypes.c_void_p,
    ]
    _wintrust.WinVerifyTrust.restype = ctypes.c_long
except OSError:
    _wintrust = None

# кеш подписей: (normcase(path), mtime_ns, size) -> bool
_SIG_CACHE = {}


def is_signed_by_microsoft(path: str) -> bool:
    """
    Валидная подпись (любая) файла через WinVerifyTrust.
    Ложные срабатывания не опасны: используется в паре с is_system_path.
    """
    if not path or not os.path.isfile(path):
        return False
    if _wintrust is None:
        return False
    try:
        st = os.stat(path)
        key = (os.path.normcase(os.path.abspath(path)),
               st.st_mtime_ns, st.st_size)
    except OSError:
        return False
    if key in _SIG_CACHE:
        return _SIG_CACHE[key]

    fi = _WINTRUST_FILE_INFO()
    fi.cbStruct = ctypes.sizeof(fi)
    fi.pcwszFilePath = path
    wd = _WINTRUST_DATA()
    wd.cbStruct = ctypes.sizeof(wd)
    wd.dwUIChoice = _WTD_UI_NONE
    wd.fdwRevocationChecks = _WTD_REVOKE_NONE
    wd.dwUnionChoice = _WTD_CHOICE_FILE
    wd.pFile = ctypes.pointer(fi)
    wd.dwStateAction = _WTD_STATEACTION_VERIFY
    wd.dwProvFlags = _WTD_PROV_FLAGS_CACHE_ONLY

    try:
        rc = _wintrust.WinVerifyTrust(None,
                                      ctypes.byref(_ACTION_GENERIC_VERIFY_V2),
                                      ctypes.byref(wd))
        ok = (rc == 0)
    finally:
        wd.dwStateAction = _WTD_STATEACTION_CLOSE
        try:
            _wintrust.WinVerifyTrust(None,
                                     ctypes.byref(_ACTION_GENERIC_VERIFY_V2),
                                     ctypes.byref(wd))
        except Exception:
            pass

    _SIG_CACHE[key] = ok
    return ok


def file_sha256(path: str) -> str:
    """SHA-256 файла (для пользовательского белого списка)."""
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Проверка «критичности» процесса (BreakOnTermination)
# ---------------------------------------------------------------------------

def is_process_critical(pid: int) -> bool:
    """
    Проверить, помечен ли процесс как критический (BreakOnTermination != 0).

    Требует прав администратора: открывает процесс с PROCESS_QUERY_INFORMATION.
    Для PID 0 (System Idle) всегда False — открыть нельзя.
    """
    if pid <= 0:
        return False
    h = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return False
    try:
        value = wintypes.ULONG(0)
        ret_len = wintypes.ULONG(0)
        status = ntdll.NtQueryInformationProcess(
            h, ProcessBreakOnTermination,
            ctypes.byref(value), ctypes.sizeof(value),
            ctypes.byref(ret_len),
        )
        if status != 0:
            return False
        return value.value != 0
    finally:
        _kernel32.CloseHandle(h)


def is_critical_process(pid: int, path: str = "") -> bool:
    """
    'Критический' в широком смысле:
      - BreakOnTermination=1 (RtlSetProcessIsCritical), ИЛИ
      - System Idle / System, ИЛИ
      - бинарник в %SystemRoot%\\System32 или SysWOW64 с подписью Microsoft
        (smss/csrss/wininit/services/lsass/winlogon/...)
    """
    if pid in (0, 4):
        return True
    try:
        if is_process_critical(pid):
            return True
    except Exception:
        pass

    if not path:
        return False
    if not is_system_path(path):
        return False

    try:
        p = os.path.normcase(os.path.abspath(path))
    except Exception:
        return False
    sys32 = os.path.normcase(os.path.join(_SYSTEM_ROOT, 'System32')) + os.sep
    syswow = os.path.normcase(os.path.join(_SYSTEM_ROOT, 'SysWOW64')) + os.sep
    if not (p.startswith(sys32) or p.startswith(syswow)):
        return False
    return is_signed_by_microsoft(path)


def is_process_suspicious(pid: int, path: str) -> bool:
    """
    Подозрительный = критический И НЕ (системный путь + подпись MS).
    Списка имён нет — только путь и подпись.
    """
    if pid in (0, 4):
        return False
    if not is_critical_process(pid, path):
        return False
    in_sys = is_system_path(path) if path else False
    signed = is_signed_by_microsoft(path) if (path and os.path.isfile(path)) else False
    return not (in_sys and signed)


# ---------------------------------------------------------------------------
# SeDebugPrivilege
# ---------------------------------------------------------------------------

def enable_debug_privilege() -> bool:
    """Включить SeDebugPrivilege в текущем процессе."""
    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.LookupPrivilegeValueW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p
    ]
    advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
    advapi32.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p,
        wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p
    ]
    advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x0002

    class LUID(ctypes.Structure):
        _fields_ = [('LowPart', wintypes.DWORD), ('HighPart', wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [('Luid', LUID), ('Attributes', wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [('PrivilegeCount', wintypes.DWORD),
                    ('Privileges', LUID_AND_ATTRIBUTES * 1)]

    h_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(h_token)):
        print(f"OpenProcessToken failed: {ctypes.get_last_error()}")
        return False

    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(
                None, 'SeDebugPrivilege', ctypes.byref(luid)):
            print(f"LookupPrivilegeValue failed: {ctypes.get_last_error()}")
            return False

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        if not advapi32.AdjustTokenPrivileges(
                h_token, False, ctypes.byref(tp), 0, None, None):
            print(f"AdjustTokenPrivileges failed: {ctypes.get_last_error()}")
            return False

        err = ctypes.get_last_error()
        if err != 0:
            print(f"AdjustTokenPrivileges last_error={err} (1300 = NOT_ALL_ASSIGNED)")
            return False
        return True
    finally:
        kernel32.CloseHandle(h_token)


class ProcessManager:
    """Класс для управления процессами."""

    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ntdll
        self.has_debug_priv = enable_debug_privilege()
        if not self.has_debug_priv:
            logger.warning("SeDebugPrivilege не включён — часть процессов "
                           "будет недоступна для проверки критичности")

    # ---------- перечисление ----------
    def get_processes(self) -> list:
        processes = []
        try:
            for pid, name, ppid in _toolhelp_snapshot():
                processes.append({
                    'name': name, 'pid': pid, 'ppid': ppid,
                    'path': get_process_path(pid),
                    'memory': '', 'status': '', 'user': '',
                })
        except Exception as e:
            logger.error(f"Ошибка получения процессов (Toolhelp32): {e}")
            return processes

        try:
            extra = self._tasklist_extra_info()
            for proc in processes:
                info = extra.get(proc['pid'])
                if info:
                    proc.update(info)
        except Exception as e:
            logger.debug(f"tasklist недоступен (нормально для WinPE): {e}")

        return processes

    def _tasklist_extra_info(self) -> dict:
        result = {}
        cmd_result = run_hidden_command('tasklist /fo CSV /nh /v', capture_output=True)
        stdout = decode_output(cmd_result.stdout) if cmd_result.stdout else ""
        for line in stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split('","')
            if len(parts) >= 7:
                try:
                    pid = int(parts[1].strip('"'))
                    result[pid] = {
                        'memory': parts[4].strip('"'),
                        'user': parts[5].strip('"'),
                        'status': parts[6].strip('"'),
                    }
                except (ValueError, IndexError):
                    pass
        return result

    # ---------- хендлы ----------
    def open_process(self, pid: int, access: int = PROCESS_QUERY_INFORMATION) -> int:
        try:
            return self.kernel32.OpenProcess(access, False, pid) or 0
        except Exception as e:
            logger.error(f"Ошибка открытия процесса {pid}: {e}")
            return 0

    def close_process(self, handle: int) -> bool:
        try:
            self.kernel32.CloseHandle(handle)
            return True
        except Exception:
            return False

    # ---------- действия ----------
    def terminate_process(self, pid: int) -> bool:
        try:
            handle = self.open_process(pid, PROCESS_TERMINATE)
            if handle:
                result = self.kernel32.TerminateProcess(handle, 0)
                self.close_process(handle)
                logger.info(f"Процесс {pid} завершён")
                return bool(result)
            return False
        except Exception as e:
            logger.error(f"Ошибка завершения процесса {pid}: {e}")
            return False

    def suspend_process(self, pid: int) -> bool:
        try:
            handle = self.open_process(pid, PROCESS_SUSPEND_RESUME)
            if handle:
                result = self.ntdll.NtSuspendProcess(handle)
                self.close_process(handle)
                if result == 0:
                    logger.info(f"Процесс {pid} заморожен")
                    return True
            return False
        except Exception as e:
            logger.error(f"Ошибка заморозки процесса {pid}: {e}")
            return False

    def resume_process(self, pid: int) -> bool:
        try:
            handle = self.open_process(pid, PROCESS_SUSPEND_RESUME)
            if handle:
                result = self.ntdll.NtResumeProcess(handle)
                self.close_process(handle)
                if result == 0:
                    logger.info(f"Процесс {pid} разморожен")
                    return True
            return False
        except Exception as e:
            logger.error(f"Ошибка разморозки процесса {pid}: {e}")
            return False

    # ---------- критичность ----------
    def is_process_critical(self, pid: int) -> bool:
        """Обёртка над модульной функцией (для удобства)."""
        return is_process_critical(pid)

    def get_critical_map(self) -> dict:
        """{pid: is_critical} — учитывая системные критические процессы."""
        result = {}
        for pid, _name, _ppid in _toolhelp_snapshot():
            path = get_process_path(pid)
            try:
                result[pid] = is_critical_process(pid, path)
            except Exception:
                result[pid] = (pid in (0, 4))
        return result

    def is_critical_process(self, pid: int, path: str = "") -> bool:
        """Обёртка над модульной функцией (для удобства)."""
        return is_critical_process(pid, path)

    def is_process_suspicious(self, pid: int, path: str) -> bool:
        """Обёртка над модульной функцией (для удобства)."""
        return is_process_suspicious(pid, path)

    def remove_critical_flag(self, pid: int) -> bool:
        """Снять флаг 'критический процесс'. Нужен админ + PROCESS_ALL_ACCESS."""
        try:
            handle = self.open_process(pid, PROCESS_ALL_ACCESS)
            if not handle:
                logger.error(f"remove_critical_flag: OpenProcess({pid}) == 0, "
                             f"last_error={ctypes.get_last_error()}")
                return False
            try:
                value = ctypes.c_int(0)
                status = self.ntdll.NtSetInformationProcess(
                    handle, ProcessBreakOnTermination,
                    ctypes.byref(value), ctypes.sizeof(value),
                )
                if status == 0:
                    logger.info(f"Критический флаг снят с процесса {pid}")
                    return True
                logger.error(f"NtSetInformationProcess NTSTATUS=0x{status & 0xFFFFFFFF:08X}")
                if status & 0xFFFFFFFF == 0xC0000022:
                    logger.error("STATUS_ACCESS_DENIED — нужны права администратора")
                return False
            finally:
                self.close_process(handle)
        except Exception as e:
            logger.error(f"Ошибка снятия флага критичности: {e}")
            return False

    def safe_terminate_critical(self, pid: int) -> dict:
        """
        Безопасно нейтрализовать критический процесс:
          1) suspend  (чтобы не успел обратно выставить флаг)
          2) unmark   (NtSetInformationProcess 0x1D = 0)
          3) kill     (TerminateProcess)
          4) если kill провалился — resume
        """
        result = {'success': False, 'stage': 'init', 'error': ''}

        if not self.suspend_process(pid):
            result['stage'] = 'suspend'
            result['error'] = 'Не удалось заморозить процесс'
            return result
        result['stage'] = 'suspend'

        if not self.remove_critical_flag(pid):
            self.resume_process(pid)
            result['stage'] = 'unmark'
            result['error'] = ('Не удалось снять флаг критичности '
                               '(нужны права администратора и SeDebugPrivilege)')
            return result
        result['stage'] = 'unmark'

        if not self.terminate_process(pid):
            self.resume_process(pid)
            result['stage'] = 'terminate'
            result['error'] = 'Флаг снят, но TerminateProcess не удался'
            return result

        result['success'] = True
        result['stage'] = 'done'
        return result

    # ---------- эвристика ----------
    def find_suspicious_critical(self) -> list:
        out = []
        for proc in self.get_processes():
            pid = proc['pid']
            if pid in (0, 4):
                continue
            path = proc.get('path') or ''
            try:
                if not is_critical_process(pid, path):
                    continue
                if not is_process_suspicious(pid, path):
                    continue
            except Exception:
                continue
            in_sys = is_system_path(path) if path else False
            out.append({
                'pid': pid,
                'name': proc.get('name'),
                'path': path,
                'reason': ('Критический процесс вне %SystemRoot% без подписи'
                           if not in_sys else
                           'Критический процесс в %SystemRoot% без подписи MS'),
            })
        return out

    # ---------- прочее ----------
    def set_priority(self, pid: int, priority: int) -> bool:
        try:
            handle = self.open_process(pid, PROCESS_SET_INFORMATION)
            if handle:
                result = self.kernel32.SetPriorityClass(handle, priority)
                self.close_process(handle)
                return bool(result)
            return False
        except Exception as e:
            logger.error(f"Ошибка установки приоритета: {e}")
            return False

    def kill_process_tree(self, pid: int) -> bool:
        try:
            ps_command = f'''
            Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {pid} }} | ForEach-Object {{
                Stop-Process -Id $_.ProcessId -Force
            }}
            '''
            run_hidden_powershell(ps_command)
            return self.terminate_process(pid)
        except Exception as e:
            logger.error(f"Ошибка удаления дерева процессов: {e}")
            return False

    def find_process_by_name(self, name: str) -> list:
        name_lower = name.lower()
        return [p for p in self.get_processes()
                if name_lower in (p['name'] or '').lower()]


# ---------- быстрые функции ----------
def get_processes():
    return ProcessManager().get_processes()


def get_process_location(pid: int) -> str:
    return get_process_path(pid)


def terminate_process(pid: int):
    return ProcessManager().terminate_process(pid)


def suspend_process(pid: int):
    return ProcessManager().suspend_process(pid)


def resume_process(pid: int):
    return ProcessManager().resume_process(pid)
"""
Модуль управления процессами Windows
Критичность определяется через kernel32.IsProcessCritical (Win8+) с fallback на NtQueryInformationProcess
"""

import ctypes
from ctypes import wintypes
import subprocess
import logging
import os

CREATE_NO_WINDOW = 0x08000000

PROCESS_TERMINATE = 0x0001
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_SET_INFORMATION = 0x0200
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_ALL_ACCESS = 0x001F0FFF

IDLE_PRIORITY_CLASS = 0x00000040
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
NORMAL_PRIORITY_CLASS = 0x00000020
ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
HIGH_PRIORITY_CLASS = 0x00000080
REALTIME_PRIORITY_CLASS = 0x00000100

logger = logging.getLogger(__name__)

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Явно объявляем сигнатуры — иначе ctypes на 64-бит может неправильно маршалить
try:
    kernel32.IsProcessCritical.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel32.IsProcessCritical.restype = wintypes.BOOL
    _HAS_IS_CRITICAL = True
except AttributeError:
    _HAS_IS_CRITICAL = False

ntdll.NtQueryInformationProcess.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
    ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
]
ntdll.NtQueryInformationProcess.restype = ctypes.c_long

ntdll.NtSetInformationProcess.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong
]
ntdll.NtSetInformationProcess.restype = ctypes.c_long


def get_process_path(pid: int) -> str:
    """Получить путь к файлу процесса через WinAPI"""
    MAX_PATH = 260
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return "N/A"
    try:
        buf = ctypes.create_unicode_buffer(MAX_PATH)
        size = ctypes.c_uint(MAX_PATH)
        result = kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
        if result:
            return buf.value
        return "N/A"
    finally:
        kernel32.CloseHandle(handle)


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
        cmd,
        shell=True,
        capture_output=capture_output,
        startupinfo=startupinfo,
        creationflags=CREATE_NO_WINDOW
    )


def run_hidden_powershell(ps_command: str, capture_output: bool = True, random_name: bool = True) -> subprocess.CompletedProcess:
    import tempfile
    import shutil

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    if random_name:
        temp_dir = tempfile.mkdtemp(prefix='PS_')
        ps_exe = os.path.join(
            os.environ.get('SystemRoot', r'C:\Windows'),
            'System32\\WindowsPowerShell\\v1.0\\powershell.exe'
        )
        random_name_file = generate_random_name(12) + '.exe'
        ps_copy = os.path.join(temp_dir, random_name_file)
        try:
            shutil.copy2(ps_exe, ps_copy)
        except Exception as e:
            logger.error(f"Не удалось создать копию PowerShell: {e}")
            ps_copy = ps_exe
        return subprocess.run(
            [ps_copy, '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
            capture_output=capture_output,
            startupinfo=startupinfo,
            creationflags=CREATE_NO_WINDOW
        )
    else:
        return subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
            capture_output=capture_output,
            startupinfo=startupinfo,
            creationflags=CREATE_NO_WINDOW
        )


def decode_output(stdout_bytes: bytes) -> str:
    if not stdout_bytes:
        return ""
    for encoding in ('utf-8', 'utf-8-sig', 'cp866', 'cp1251'):
        try:
            return stdout_bytes.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return stdout_bytes.decode('utf-8', errors='replace')


class ProcessManager:
    """Класс для управления процессами (методы из SimpleUnlocker TMCore.cs)"""

    def __init__(self):
        self.kernel32 = kernel32
        self.ntdll = ntdll

    # ---------- Получение списка ----------

    def get_processes(self) -> list:
        """Список процессов. chcp 65001 для корректной кириллицы."""
        processes = []
        try:
            result = run_hidden_command(
                'chcp 65001 > nul && tasklist /fo CSV /nh /v',
                capture_output=True
            )
            stdout = decode_output(result.stdout) if result.stdout else ""

            for line in stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split('","')
                if len(parts) >= 7:
                    try:
                        pid = int(parts[1].strip('"'))
                        processes.append({
                            'name': parts[0].strip('"'),
                            'pid': pid,
                            'memory': parts[4].strip('"'),
                            'status': parts[6].strip('"'),
                            'user': parts[5].strip('"')
                        })
                    except (ValueError, IndexError):
                        pass
        except Exception as e:
            logger.error(f"Ошибка получения процессов: {e}")
        return processes

    def get_processes_with_paths(self) -> list:
        """Список процессов с путями (без проверки критичности)"""
        processes = self.get_processes()
        for proc in processes:
            proc['path'] = get_process_path(proc['pid'])
        return processes

    def get_processes_with_paths_and_criticality(self) -> list:
        """Список процессов с путями и флагом критичности"""
        processes = self.get_processes()
        for proc in processes:
            proc['path'] = get_process_path(proc['pid'])
            try:
                proc['critical'] = self.is_process_critical(proc['pid'])
            except Exception:
                proc['critical'] = False
        return processes

    # ---------- Работа с дескрипторами ----------

    def open_process(self, pid: int, access: int = PROCESS_QUERY_INFORMATION) -> int:
        try:
            return self.kernel32.OpenProcess(access, False, pid)
        except Exception as e:
            logger.error(f"Ошибка открытия процесса {pid}: {e}")
            return 0

    def close_process(self, handle: int) -> bool:
        try:
            self.kernel32.CloseHandle(handle)
            return True
        except Exception:
            return False

    # ---------- Основные операции ----------

    def terminate_process(self, pid: int) -> bool:
        try:
            handle = self.open_process(pid, PROCESS_TERMINATE)
            if handle:
                result = self.kernel32.TerminateProcess(handle, 0)
                self.close_process(handle)
                return result != 0
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
                return result == 0
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
                return result == 0
            return False
        except Exception as e:
            logger.error(f"Ошибка разморозки процесса {pid}: {e}")
            return False

    # ---------- Критичность ---------

    def is_process_critical(self, pid: int) -> bool:
        """Критичность по имени процесса — работает без API и без прав."""
        if pid in (0, 4):
            return True

        critical_names = {
            'system', 'registry', 'idle',
            'memory compression', 'memcompression', 'secure system',
            'smss', 'csrss', 'wininit', 'services',
            'lsass', 'winlogon', 'fontdrvhost',
        }

        try:
            r = run_hidden_command(
                f'tasklist /fi "PID eq {pid}" /fo csv /nh',
                capture_output=True
            )
            if not r.stdout:
                return False
            out = decode_output(r.stdout)
            for line in out.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                parts = line.split('","')
                if not parts:
                    continue
                name = parts[0].strip('"').lower()
                bare = name[:-4] if name.endswith('.exe') else name
                if bare in critical_names:
                    return True
        except Exception as e:
            logger.debug(f"critical check {pid}: {e}")
        return False

    def remove_critical_flag(self, pid: int) -> bool:
        """Снять флаг критичности (ProcessBreakOnTermination)"""
        try:
            BreakOnTermination = 0x1D
            handle = self.open_process(pid, PROCESS_ALL_ACCESS)
            if not handle:
                return False
            try:
                is_critical = ctypes.c_int(0)
                result = self.ntdll.NtSetInformationProcess(
                    handle, BreakOnTermination,
                    ctypes.byref(is_critical), ctypes.sizeof(ctypes.c_int)
                )
                return result == 0
            finally:
                self.close_process(handle)
        except Exception as e:
            logger.error(f"Ошибка снятия флага критичности: {e}")
            return False

    # ---------- Прочее ----------

    def set_priority(self, pid: int, priority: int) -> bool:
        try:
            handle = self.open_process(pid, PROCESS_SET_INFORMATION)
            if handle:
                result = self.kernel32.SetPriorityClass(handle, priority)
                self.close_process(handle)
                return result != 0
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
        result = []
        name_lower = name.lower()
        for proc in self.get_processes():
            if name_lower in proc['name'].lower():
                result.append(proc)
        return result


# Функции для быстрого доступа
def get_processes():
    return ProcessManager().get_processes()


def terminate_process(pid: int):
    return ProcessManager().terminate_process(pid)


def suspend_process(pid: int):
    return ProcessManager().suspend_process(pid)


def resume_process(pid: int):
    return ProcessManager().resume_process(pid)
"""
AntiGDI - Защита от GDI-атак (зависание процессов через GDI объекты)

AntiGDI из SimpleUnlocker предотвращает атаки типа "GDI handle leak",
которые могут привести к зависанию системы.

Принцип работы:
- Внедряет DLL в выбранный процесс
- Перехватывает GDI-функции
- Предотвращает утечку GDI-объектов
"""

import subprocess
import os
import logging
import ctypes
from ctypes import wintypes

# Константа для скрытия окна консоли
CREATE_NO_WINDOW = 0x08000000

logger = logging.getLogger(__name__)

# Процессорные архитектуры
ARCH_X86 = "x86"
ARCH_X64 = "x64"


def run_hidden_command(cmd: str, capture_output: bool = False) -> subprocess.CompletedProcess:
    """Выполнить команду без показа окна консоли"""
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    return subprocess.run(
        cmd,
        shell=True,
        capture_output=capture_output,
        text=True,
        startupinfo=startupinfo,
        creationflags=CREATE_NO_WINDOW
    )


def get_process_architecture(pid: int) -> str:
    """
    Определить архитектуру процесса (x86 или x64)
    
    Args:
        pid: ID процесса
        
    Returns:
        str: ARCH_X86 или ARCH_X64
    """
    try:
        # Используем PowerShell для определения архитектуры
        ps_script = f'''
        $proc = Get-Process -Id {pid} -ErrorAction SilentlyContinue
        if ($proc) {{
            $is64Bit = $proc.MainModule.FileVersionInfo.Is64Bit
            if ($is64Bit) {{
                Write-Output "x64"
            }} else {{
                Write-Output "x86"
            }}
        }} else {{
            Write-Output "unknown"
        }}
        '''
        
        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True,
            text=True
        )
        
        output = result.stdout.strip().lower()
        if 'x64' in output:
            return ARCH_X64
        elif 'x86' in output:
            return ARCH_X86
        else:
            return ARCH_X86  # По умолчанию x86
    except Exception as e:
        logger.error(f"Ошибка определения архитектуры процесса {pid}: {e}")
        return ARCH_X86


def is_process_suspended(pid: int) -> bool:
    """
    Проверить, приостановлен ли процесс
    
    Args:
        pid: ID процесса
        
    Returns:
        bool: True если процесс приостановлен
    """
    try:
        ps_script = f'''
        $proc = Get-Process -Id {pid} -ErrorAction SilentlyContinue
        if ($proc) {{
            $threads = $proc.Threads
            foreach ($thread in $threads) {{
                if ($thread.ThreadState -eq [System.Diagnostics.ThreadState]::Wait -and 
                    $thread.WaitReason -eq [System.Diagnostics.ThreadWaitReason]::Suspended) {{
                    Write-Output "suspended"
                    break
                }}
            }}
        }}
        '''
        
        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True,
            text=True
        )
        
        return 'suspended' in result.stdout.lower()
    except Exception:
        return False


def get_suspended_processes() -> list:
    """
    Получить список приостановленных процессов
    
    Returns:
        list: Список словарей с информацией о процессах
    """
    suspended = []
    
    try:
        ps_script = '''
        $processes = Get-Process
        foreach ($proc in $processes) {
            try {
                $isSuspended = $false
                foreach ($thread in $proc.Threads) {
                    if ($thread.ThreadState -eq [System.Diagnostics.ThreadState]::Wait -and 
                        $thread.WaitReason -eq [System.Diagnostics.ThreadWaitReason]::Suspended) {
                        $isSuspended = $true
                        break
                    }
                }
                if ($isSuspended) {
                    $is64Bit = $false
                    try {
                        $is64Bit = $proc.MainModule.FileVersionInfo.Is64Bit
                    } catch {}
                    [PSCustomObject]@{
                        Id = $proc.Id
                        Name = $proc.ProcessName
                        Arch = if ($is64Bit) { "x64" } else { "x86" }
                    }
                }
            } catch {}
        }
        '''
        
        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True,
            text=True
        )
        
        # Парсим вывод PowerShell
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        suspended.append({
                            'id': int(parts[0]),
                            'name': parts[1],
                            'arch': parts[2]
                        })
                    except ValueError:
                        continue
    except Exception as e:
        logger.error(f"Ошибка получения списка процессов: {e}")
    
    return suspended


def inject_antigdi(pid: int, modules_dir: str = None) -> dict:
    """
    Внедрить AntiGDI в процесс

    Args:
        pid: ID процесса для внедрения
        modules_dir: Путь к папке modules с AntiGDI файлами

    Returns:
        dict: Результат операции
    """
    result = {
        'success': False,
        'message': '',
        'pid': pid
    }

    # Определяем путь к модулям
    if modules_dir is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        modules_dir = script_dir

    # Пробуем использовать Python-инжектор (надёжнее)
    try:
        from .antigdi_injector import inject_antigdi_python
        logger.info(f"Использование Python-инжектора для процесса {pid}")
        return inject_antigdi_python(pid, modules_dir)
    except ImportError as e:
        logger.warning(f"Не удалось импортировать Python-инжектор: {e}. Пробуем EXE-инжектор.")
    
    # Фоллбэк на EXE-инжектор
    injector_path = os.path.join(modules_dir, 'AntiGDI_Injector.exe')
    antigdi_dll = os.path.join(modules_dir, 'AntiGDI.dll')

    if not os.path.exists(injector_path):
        result['message'] = f'AntiGDI_Injector.exe не найден: {injector_path}'
        return result

    if not os.path.exists(antigdi_dll):
        result['message'] = f'AntiGDI.dll не найден: {antigdi_dll}'
        return result

    # Определяем архитектуру процесса
    arch = get_process_architecture(pid)
    logger.info(f"Процесс {pid} архитектура: {arch}")

    try:
        # Запускаем инжектор с PID процесса и путём к DLL
        cmd = f'"{injector_path}" "{antigdi_dll}" {pid}'
        logger.info(f"Запуск AntiGDI инжектора: {cmd}")

        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        process = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            startupinfo=startupinfo,
            creationflags=CREATE_NO_WINDOW
        )

        if process.returncode == 0:
            result['success'] = True
            result['message'] = f'AntiGDI успешно внедрён в процесс {pid}'
        else:
            error_msg = process.stderr.strip() if process.stderr else "Неизвестная ошибка"
            result['message'] = f'Ошибка внедрения AntiGDI. Код: {process.returncode}\n{error_msg}'
            logger.error(f"AntiGDI ошибка: {error_msg}")

    except Exception as e:
        logger.error(f"Ошибка внедрения AntiGDI: {e}")
        result['message'] = f'Ошибка: {str(e)}'

    return result


def inject_antigdi_multiple(pids: list, modules_dir: str = None) -> dict:
    """
    Внедрить AntiGDI в несколько процессов
    
    Args:
        pids: Список ID процессов
        modules_dir: Путь к папке modules
        
    Returns:
        dict: Результаты операции
    """
    results = {
        'total': len(pids),
        'success': 0,
        'failed': 0,
        'details': []
    }
    
    for pid in pids:
        result = inject_antigdi(pid, modules_dir)
        results['details'].append(result)
        
        if result['success']:
            results['success'] += 1
        else:
            results['failed'] += 1
    
    return results


def check_process_gdi_handles(pid: int) -> dict:
    """
    Проверить количество GDI-объектов у процесса
    
    Args:
        pid: ID процесса
        
    Returns:
        dict: Информация о GDI-объектах
    """
    result = {
        'pid': pid,
        'gdi_objects': 0,
        'user_objects': 0,
        'status': 'unknown'
    }
    
    try:
        ps_script = f'''
        $proc = Get-Process -Id {pid} -ErrorAction SilentlyContinue
        if ($proc) {{
            $gdiObjects = $proc.GDIObjects
            $userObjects = $proc.UserObjects
            
            # Лимиты Windows
            $gdiLimit = 10000
            $userLimit = 10000
            
            $gdiPercent = [math]::Round(($gdiObjects / $gdiLimit) * 100, 2)
            $userPercent = [math]::Round(($userObjects / $userLimit) * 100, 2)
            
            Write-Output "$gdiObjects|$userObjects|$gdiPercent|$userPercent"
        }}
        '''
        
        proc_result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True,
            text=True
        )
        
        if proc_result.stdout.strip():
            parts = proc_result.stdout.strip().split('|')
            if len(parts) >= 4:
                result['gdi_objects'] = int(parts[0])
                result['user_objects'] = int(parts[1])
                gdi_percent = float(parts[2])
                user_percent = float(parts[3])
                
                if gdi_percent > 80 or user_percent > 80:
                    result['status'] = 'warning'
                elif gdi_percent > 90 or user_percent > 90:
                    result['status'] = 'critical'
                else:
                    result['status'] = 'normal'
    except Exception as e:
        logger.error(f"Ошибка проверки GDI-объектов: {e}")
    
    return result


class AntiGDIManager:
    """Менеджер для управления AntiGDI"""
    
    def __init__(self, modules_dir: str = None):
        """
        Инициализация менеджера
        
        Args:
            modules_dir: Путь к папке modules
        """
        if modules_dir is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            self.modules_dir = script_dir
        else:
            self.modules_dir = modules_dir
        
        self.injected_pids = []
    
    def get_suspended_processes(self) -> list:
        """Получить список приостановленных процессов"""
        return get_suspended_processes()
    
    def inject(self, pid: int) -> dict:
        """Внедрить AntiGDI в процесс"""
        result = inject_antigdi(pid, self.modules_dir)
        if result['success']:
            self.injected_pids.append(pid)
        return result
    
    def inject_multiple(self, pids: list) -> dict:
        """Внедрить AntiGDI в несколько процессов"""
        results = inject_antigdi_multiple(pids, self.modules_dir)
        for result in results['details']:
            if result['success']:
                self.injected_pids.append(result['pid'])
        return results
    
    def check_gdi_handles(self, pid: int) -> dict:
        """Проверить GDI-объекты процесса"""
        return check_process_gdi_handles(pid)
    
    def get_injected_processes(self) -> list:
        """Получить список процессов с внедрённым AntiGDI"""
        return self.injected_pids.copy()
    
    def clear_injected(self):
        """Очистить список внедрённых процессов"""
        self.injected_pids.clear()


# Функции для быстрого доступа
def inject_antigdi_quick(pid: int, modules_dir: str = None) -> bool:
    """Быстрое внедрение AntiGDI"""
    result = inject_antigdi(pid, modules_dir)
    return result['success']


def get_suspended_quick() -> list:
    """Быстрое получение списка приостановленных процессов"""
    return get_suspended_processes()

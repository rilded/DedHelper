"""
Снятие флага критичности с процессов (метод из SimpleUnlocker TMCore.cs)

Использует NtSetInformationProcess из ntdll.dll для снятия флага ProcessBreakOnTermination
"""

import ctypes
from ctypes import wintypes
import logging
import subprocess

logger = logging.getLogger(__name__)

# Загружаем ntdll
ntdll = ctypes.windll.ntdll

# Константы
PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_SET_INFORMATION = 0x00000200
PROCESS_QUERY_INFORMATION = 0x00000400

# ProcessBreakOnTermination = 0x1D (29)
BREAK_ON_TERMINATION = 0x1D


# Импорты из ntdll.dll
try:
    # NtSetInformationProcess для снятия критичности
    ntdll.NtSetInformationProcess.argtypes = [
        wintypes.HANDLE,  # hProcess
        ctypes.c_int,     # processInformationClass
        ctypes.c_void_p,  # processInformation
        ctypes.c_int      # processInformationLength
    ]
    ntdll.NtSetInformationProcess.restype = ctypes.c_int

    # NtQueryInformationProcess для проверки критичности
    ntdll.NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE,  # hProcess
        ctypes.c_uint,    # processInformationClass
        ctypes.c_void_p,  # processInformation
        ctypes.c_uint,    # processInformationLength
        ctypes.c_void_p   # returnLength
    ]
    ntdll.NtQueryInformationProcess.restype = ctypes.c_int

    # NtSuspendProcess для заморозки
    ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtSuspendProcess.restype = ctypes.c_int

    # NtResumeProcess для разморозки
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = ctypes.c_int

except Exception as e:
    logger.error(f"Ошибка загрузки функций ntdll: {e}")


def open_process(pid: int, access: int = PROCESS_ALL_ACCESS) -> wintypes.HANDLE:
    """
    Открыть процесс с указанными правами доступа
    
    Args:
        pid: ID процесса
        access: Права доступа
        
    Returns:
        HANDLE процесса или None
    """
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.argtypes = [
            ctypes.c_int,  # dwDesiredAccess
            ctypes.c_bool, # bInheritHandle
            ctypes.c_int   # dwProcessId
        ]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        
        handle = kernel32.OpenProcess(access, False, pid)
        
        if handle == 0 or handle is None:
            error = ctypes.get_last_error()
            logger.error(f"Не удалось открыть процесс {pid}. Ошибка: {error}")
            return None
            
        return handle
    except Exception as e:
        logger.error(f"Ошибка открытия процесса: {e}")
        return None


def close_handle(handle: wintypes.HANDLE) -> bool:
    """
    Закрыть HANDLE
    
    Args:
        handle: HANDLE для закрытия
        
    Returns:
        bool: True если успешно
    """
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = ctypes.c_bool
        
        return kernel32.CloseHandle(handle)
    except Exception as e:
        logger.error(f"Ошибка закрытия HANDLE: {e}")
        return False


def is_process_critical(pid: int) -> bool:
    """
    Проверить, является ли процесс критическим (метод из SimpleUnlocker TMCore.cs)
    
    Args:
        pid: ID процесса
        
    Returns:
        bool: True если критический
    """
    handle = None
    try:
        handle = open_process(pid, PROCESS_QUERY_INFORMATION)
        
        if handle is None:
            return False
        
        value = ctypes.c_uint(0)
        size = ctypes.c_uint(0)
        
        # NtQueryInformationProcess с ProcessBreakOnTermination (29)
        result = ntdll.NtQueryInformationProcess(
            handle,
            29,  # ProcessBreakOnTermination
            ctypes.byref(value),
            ctypes.sizeof(ctypes.c_uint),
            ctypes.byref(size)
        )
        
        if result != 0 or size.value != ctypes.sizeof(ctypes.c_uint):
            return False
        
        is_critical = value.value != 0
        logger.debug(f"Процесс {pid} критический: {is_critical}")
        return is_critical
        
    except Exception as e:
        logger.error(f"Ошибка проверки критичности процесса {pid}: {e}")
        return False
    finally:
        if handle:
            close_handle(handle)


def remove_process_critical(pid: int) -> dict:
    """
    Снять флаг критичности с процесса (метод из SimpleUnlocker TMCore.cs)
    
    Args:
        pid: ID процесса
        
    Returns:
        dict: Результат операции
    """
    result = {
        'success': False,
        'message': '',
        'pid': pid,
        'was_critical': False
    }
    
    handle = None
    try:
        # Проверяем, критический ли процесс
        was_critical = is_process_critical(pid)
        result['was_critical'] = was_critical
        
        if not was_critical:
            result['success'] = True
            result['message'] = f'Процесс {pid} не является критическим'
            return result
        
        # Открываем процесс с правами SET_INFORMATION
        handle = open_process(pid, PROCESS_SET_INFORMATION)
        
        if handle is None:
            result['message'] = f'Не удалось открыть процесс {pid}'
            return result
        
        # Снимаем флаг критичности (устанавливаем в 0)
        # BreakOnTermination = 0x1D
        is_critical = ctypes.c_int(0)  # 0 = не критический
        
        status = ntdll.NtSetInformationProcess(
            handle,
            BREAK_ON_TERMINATION,  # 0x1D = ProcessBreakOnTermination
            ctypes.byref(is_critical),
            ctypes.sizeof(ctypes.c_int)
        )
        
        if status == 0:
            result['success'] = True
            result['message'] = f'Флаг критичности успешно снят с процесса {pid}'
            logger.info(f"Флаг критичности снят с процесса {pid}")
        else:
            # Преобразуем NTSTATUS в понятное сообщение
            if status == 0xC0000022:  # STATUS_ACCESS_DENIED
                result['message'] = f'Отказано в доступе к процессу {pid}. Запустите от имени администратора.'
            else:
                result['message'] = f'Ошибка NtSetInformationProcess. Статус: 0x{status:08X}'
            logger.error(f"Ошибка снятия критичности процесса {pid}: 0x{status:08X}")
            
    except Exception as e:
        logger.error(f"Ошибка снятия критичности процесса {pid}: {e}")
        result['message'] = f'Исключение: {str(e)}'
    finally:
        if handle:
            close_handle(handle)
    
    return result


def suspend_process(pid: int) -> dict:
    """
    Заморозить процесс (метод из SimpleUnlocker Utils.cs)
    
    Args:
        pid: ID процесса
        
    Returns:
        dict: Результат операции
    """
    result = {
        'success': False,
        'message': '',
        'pid': pid
    }
    
    handle = None
    try:
        handle = open_process(pid, PROCESS_ALL_ACCESS)
        
        if handle is None:
            result['message'] = f'Не удалось открыть процесс {pid}'
            return result
        
        status = ntdll.NtSuspendProcess(handle)
        
        if status == 0:
            result['success'] = True
            result['message'] = f'Процесс {pid} успешно заморожен'
            logger.info(f"Процесс {pid} заморожен")
        else:
            result['message'] = f'Ошибка заморозки процесса. Статус: 0x{status:08X}'
            logger.error(f"Ошибка заморозки процесса {pid}: 0x{status:08X}")
            
    except Exception as e:
        logger.error(f"Ошибка заморозки процесса {pid}: {e}")
        result['message'] = f'Исключение: {str(e)}'
    finally:
        if handle:
            close_handle(handle)
    
    return result


def resume_process(pid: int) -> dict:
    """
    Разморозить процесс (метод из SimpleUnlocker Utils.cs)
    
    Args:
        pid: ID процесса
        
    Returns:
        dict: Результат операции
    """
    result = {
        'success': False,
        'message': '',
        'pid': pid
    }
    
    handle = None
    try:
        handle = open_process(pid, PROCESS_ALL_ACCESS)
        
        if handle is None:
            result['message'] = f'Не удалось открыть процесс {pid}'
            return result
        
        status = ntdll.NtResumeProcess(handle)
        
        if status == 0:
            result['success'] = True
            result['message'] = f'Процесс {pid} успешно разморожен'
            logger.info(f"Процесс {pid} разморожен")
        else:
            result['message'] = f'Ошибка разморозки процесса. Статус: 0x{status:08X}'
            logger.error(f"Ошибка разморозки процесса {pid}: 0x{status:08X}")
            
    except Exception as e:
        logger.error(f"Ошибка разморозки процесса {pid}: {e}")
        result['message'] = f'Исключение: {str(e)}'
    finally:
        if handle:
            close_handle(handle)
    
    return result


def kill_process(pid: int, remove_critical_first: bool = True) -> dict:
    """
    Завершить процесс с предварительным снятием критичности (метод из SimpleUnlocker)
    
    Args:
        pid: ID процесса
        remove_critical_first: Снимать ли флаг критичности перед завершением
        
    Returns:
        dict: Результат операции
    """
    result = {
        'success': False,
        'message': '',
        'pid': pid,
        'critical_removed': False
    }
    
    try:
        # Проверяем критичность
        was_critical = is_process_critical(pid)
        
        # Снимаем критичность если нужно
        if was_critical and remove_critical_first:
            critical_result = remove_process_critical(pid)
            if critical_result['success']:
                result['critical_removed'] = True
                logger.info(f"Снят флаг критичности с процесса {pid}")
            else:
                logger.warning(f"Не удалось снять критичность: {critical_result['message']}")
        
        # Завершаем процесс
        kernel32 = ctypes.windll.kernel32
        kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, ctypes.c_uint]
        kernel32.TerminateProcess.restype = ctypes.c_bool
        
        handle = open_process(pid, PROCESS_ALL_ACCESS)
        
        if handle is None:
            result['message'] = f'Не удалось открыть процесс {pid}'
            return result
        
        # Завершаем с кодом выхода 1
        if kernel32.TerminateProcess(handle, 1):
            result['success'] = True
            result['message'] = f'Процесс {pid} успешно завершён'
            logger.info(f"Процесс {pid} завершён")
        else:
            error = ctypes.get_last_error()
            result['message'] = f'Ошибка завершения процесса. Ошибка: {error}'
            logger.error(f"Ошибка завершения процесса {pid}: {error}")
            
    except Exception as e:
        logger.error(f"Ошибка завершения процесса {pid}: {e}")
        result['message'] = f'Исключение: {str(e)}'
    finally:
        if handle:
            close_handle(handle)
    
    return result


class ProcessCriticalManager:
    """Менеджер для управления критичностью процессов"""
    
    def __init__(self):
        self.critical_removed_pids = []
    
    def is_critical(self, pid: int) -> bool:
        """Проверить критичность процесса"""
        return is_process_critical(pid)
    
    def remove_critical(self, pid: int) -> dict:
        """Снять флаг критичности"""
        result = remove_process_critical(pid)
        if result['success']:
            self.critical_removed_pids.append(pid)
        return result
    
    def suspend(self, pid: int) -> dict:
        """Заморозить процесс"""
        return suspend_process(pid)
    
    def resume(self, pid: int) -> dict:
        """Разморозить процесс"""
        return resume_process(pid)
    
    def kill(self, pid: int, remove_critical_first: bool = True) -> dict:
        """Завершить процесс"""
        result = kill_process(pid, remove_critical_first)
        if result['success']:
            if pid in self.critical_removed_pids:
                self.critical_removed_pids.remove(pid)
        return result
    
    def get_removed_critical_pids(self) -> list:
        """Получить список процессов с которых снята критичность"""
        return self.critical_removed_pids.copy()
    
    def clear_removed_list(self):
        """Очистить список"""
        self.critical_removed_pids.clear()


# Функции для быстрого доступа
def remove_critical_quick(pid: int) -> bool:
    """Быстрое снятие критичности"""
    result = remove_process_critical(pid)
    return result['success']


def is_critical_quick(pid: int) -> bool:
    """Быстрая проверка критичности"""
    return is_process_critical(pid)

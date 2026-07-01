"""
AntiGDI Injector - внедрение AntiGDI.dll в процесс
Использует CreateRemoteThread для внедрения DLL
Основано на методе из SimpleUnlocker
"""

import ctypes
from ctypes import wintypes
import logging
import os

logger = logging.getLogger(__name__)

# Константы
PROCESS_ALL_ACCESS = 0x001F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
CREATE_REMOTE_THREAD = 0x00000008

# Загружаем DLL
kernel32 = ctypes.windll.kernel32


def inject_dll(pid: int, dll_path: str) -> bool:
    """
    Внедрить DLL в процесс через CreateRemoteThread
    
    Args:
        pid: ID процесса
        dll_path: Полный путь к DLL
        
    Returns:
        bool: True если успешно
    """
    h_process = None
    try:
        # Открываем процесс
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            error = ctypes.get_last_error()
            logger.error(f"Не удалось открыть процесс {pid}. Ошибка: {error}")
            return False
        
        # Получаем адрес LoadLibraryA
        h_kernel = ctypes.windll.kernel32.Handle
        load_library_addr = ctypes.cast(
            ctypes.windll.kernel32.LoadLibraryA,
            ctypes.c_void_p
        ).value
        
        # Выделяем память в процессе
        dll_path_bytes = dll_path.encode('ascii') + b'\x00'
        buffer_size = len(dll_path_bytes)
        
        remote_mem = kernel32.VirtualAllocEx(
            h_process,
            None,
            buffer_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
        
        if not remote_mem:
            error = ctypes.get_last_error()
            logger.error(f"Не удалось выделить память. Ошибка: {error}")
            kernel32.CloseHandle(h_process)
            return False
        
        # Записываем путь к DLL в память процесса
        written = ctypes.c_size_t()
        if not kernel32.WriteProcessMemory(
            h_process,
            remote_mem,
            dll_path_bytes,
            buffer_size,
            ctypes.byref(written)
        ):
            error = ctypes.get_last_error()
            logger.error(f"Не удалось записать память. Ошибка: {error}")
            kernel32.VirtualFreeEx(h_process, remote_mem, 0, 0x8000)  # MEM_RELEASE
            kernel32.CloseHandle(h_process)
            return False
        
        # Создаём удалённый поток для загрузки DLL
        thread_id = wintypes.DWORD()
        h_thread = kernel32.CreateRemoteThread(
            h_process,
            None,
            0,
            load_library_addr,
            remote_mem,
            0,
            ctypes.byref(thread_id)
        )
        
        if not h_thread:
            error = ctypes.get_last_error()
            logger.error(f"Не удалось создать поток. Ошибка: {error}")
            kernel32.VirtualFreeEx(h_process, remote_mem, 0, 0x8000)
            kernel32.CloseHandle(h_process)
            return False
        
        # Ждём завершения потока
        kernel32.WaitForSingleObject(h_thread, 5000)  # 5 секунд
        
        # Очищаем
        kernel32.CloseHandle(h_thread)
        kernel32.VirtualFreeEx(h_process, remote_mem, 0, 0x8000)
        kernel32.CloseHandle(h_process)
        
        logger.info(f"DLL успешно внедрена в процесс {pid}")
        return True
        
    except Exception as e:
        logger.error(f"Ошибка внедрения DLL: {e}")
        if h_process:
            kernel32.CloseHandle(h_process)
        return False


def inject_antigdi_python(pid: int, modules_dir: str = None) -> dict:
    """
    Внедрить AntiGDI.dll в процесс используя Python инжектор
    
    Args:
        pid: ID процесса
        modules_dir: Путь к папке modules
        
    Returns:
        dict: Результат операции
    """
    result = {
        'success': False,
        'message': '',
        'pid': pid
    }
    
    if modules_dir is None:
        modules_dir = os.path.dirname(os.path.abspath(__file__))
    
    antigdi_dll = os.path.join(modules_dir, 'AntiGDI.dll')
    
    if not os.path.exists(antigdi_dll):
        result['message'] = f'AntiGDI.dll не найден: {antigdi_dll}'
        return result
    
    try:
        if inject_dll(pid, antigdi_dll):
            result['success'] = True
            result['message'] = f'AntiGDI.dll успешно внедрён в процесс {pid}'
        else:
            result['message'] = f'Не удалось внедрить AntiGDI.dll в процесс {pid}'
    except Exception as e:
        logger.error(f"Ошибка внедрения AntiGDI: {e}")
        result['message'] = f'Исключение: {str(e)}'
    
    return result


if __name__ == '__main__':
    # Для тестирования
    import sys
    if len(sys.argv) >= 2:
        pid = int(sys.argv[1])
        modules_dir = sys.argv[2] if len(sys.argv) >= 3 else None
        result = inject_antigdi_python(pid, modules_dir)
        print(f"Результат: {result}")

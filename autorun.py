"""
Модуль управления автозагрузкой Windows
Управление реестром, папкой автозагрузки, планировщиком задач и службами
"""

import winreg
import os
import subprocess
import csv
import io
import logging
from pathlib import Path

# Настройка логирования
logger = logging.getLogger(__name__)


class AutorunManager:
    """Класс для управления всеми типами автозагрузки Windows"""
    
    # Ключи реестра для автозагрузки
    REGISTRY_KEYS = {
        'HKCU_Run': (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
        'HKCU_RunOnce': (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
        'HKLM_Run': (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
        'HKLM_RunOnce': (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
        'HKCU_Winlogon': (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'),
        'HKLM_Winlogon': (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'),
        'HKLM_AppInit': (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows NT\CurrentVersion\Windows'),
        'HKCU_CmdLine': (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'),
    }
    
    def __init__(self):
        self.startup_folder = self._get_startup_folder()
    
    def _get_startup_folder(self) -> str:
        """Получить путь к папке автозагрузки"""
        appdata = os.getenv('APPDATA')
        if not appdata:
            # Fallback для среды восстановления и других случаев, когда APPDATA не установлена
            appdata = os.path.expanduser(r'~\AppData\Roaming')
        return os.path.join(
            appdata,
            r'Microsoft\Windows\Start Menu\Programs\Startup'
        )
    
    # ==================== РЕЕСТР ====================
    
    def get_registry_autoruns(self) -> dict:
        """Получить все элементы автозагрузки из реестра"""
        result = {}
        
        for name, (hive, path) in self.REGISTRY_KEYS.items():
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                values = {}
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(key, i)
                        values[value_name] = value_data
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
                if values:
                    result[name] = values
            except OSError:
                result[name] = {'error': 'Нет доступа'}
        
        return result
    
    def add_registry_autorun(self, name: str, path: str, location: str = 'HKCU_Run') -> bool:
        """Добавить программу в автозагрузку через реестр"""
        try:
            hive, key_path = self.REGISTRY_KEYS.get(location, self.REGISTRY_KEYS['HKCU_Run'])
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, f'"{path}"')
            winreg.CloseKey(key)
            return True
        except Exception as e:
            return False
    
    def remove_registry_autorun(self, name: str, location: str = 'HKCU_Run') -> bool:
        """Удалить программу из автозагрузки через реестр"""
        try:
            hive, key_path = self.REGISTRY_KEYS.get(location, self.REGISTRY_KEYS['HKCU_Run'])
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            return False
    
    # ==================== ПАПКА АВТОЗАГРУЗКИ ====================
    
    def get_startup_folder_items(self) -> list:
        """Получить элементы в папке автозагрузки"""
        items = []
        try:
            for item in os.listdir(self.startup_folder):
                items.append({
                    'name': item,
                    'path': os.path.join(self.startup_folder, item)
                })
        except Exception:
            pass
        return items
    
    def add_to_startup(self, name: str, target_path: str) -> bool:
        """Добавить ярлык в папку автозагрузки"""
        try:
            shortcut_path = os.path.join(self.startup_folder, f'{name}.lnk')
            # Создаём ярлык через PowerShell
            ps_command = f'''
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WScriptShell.CreateShortcut("{shortcut_path}")
            $Shortcut.TargetPath = "{target_path}"
            $Shortcut.Save()
            '''
            subprocess.run(['powershell', '-Command', ps_command], capture_output=True)
            return True
        except Exception:
            return False
    
    def remove_from_startup(self, filename: str) -> bool:
        """Удалить элемент из папки автозагрузки"""
        try:
            filepath = os.path.join(self.startup_folder, filename)
            if os.path.exists(filepath):
                os.remove(filepath)
            return True
        except Exception:
            return False
    
    # ==================== ПЛАНИРОВЩИК ЗАДАЧ ====================

    def get_scheduled_tasks(self) -> list:
        """Получить список задач планировщика"""
        tasks = []
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'CSV', '/nh'],
                capture_output=True,
                text=True,
                encoding='cp866',
                errors='ignore'
            )
            
            # Используем csv модуль для корректного парсинга
            csv_reader = csv.reader(io.StringIO(result.stdout))
            lines = list(csv_reader)
            
            # Пропускаем заголовок (первая строка)
            for line in lines[1:]:
                if len(line) >= 2:
                    task_name = line[0].strip()
                    if task_name:  # Пропускаем пустые имена
                        tasks.append({'name': task_name})
                    else:
                        logger.debug(f"Пропущена пустая задача: {line}")
                        
        except Exception as e:
            logger.error(f"Ошибка получения задач планировщика: {e}")
            
        logger.info(f"Получено {len(tasks)} задач планировщика")
        return tasks
    
    def create_scheduled_task(self, name: str, program: str, trigger: str = 'onlogon') -> bool:
        """Создать задачу в планировщике"""
        try:
            cmd = f'schtasks /create /tn "{name}" /tr "{program}" /sc {trigger} /rl highest /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def delete_scheduled_task(self, name: str) -> bool:
        """Удалить задачу из планировщика"""
        try:
            cmd = f'schtasks /delete /tn "{name}" /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def disable_scheduled_task(self, name: str) -> bool:
        """Отключить задачу в планировщике"""
        try:
            cmd = f'schtasks /change /tn "{name}" /disable'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def enable_scheduled_task(self, name: str) -> bool:
        """Включить задачу в планировщике"""
        try:
            cmd = f'schtasks /change /tn "{name}" /enable'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    # ==================== СЛУЖБЫ ====================
    
    def get_services(self) -> list:
        """Получить список служб Windows"""
        services = []
        try:
            result = subprocess.run(
                ['sc', 'query', 'type=', 'service'],
                capture_output=True,
                text=True,
                encoding='cp866'
            )
            current_service = {}
            for line in result.stdout.split('\n'):
                if line.startswith('SERVICE_NAME:'):
                    if current_service:
                        services.append(current_service)
                    current_service = {'name': line.split(':')[1].strip()}
                elif 'DISPLAY_NAME:' in line:
                    current_service['display_name'] = line.split(':')[1].strip()
                elif 'STATE' in line:
                    if 'RUNNING' in line:
                        current_service['state'] = 'running'
                    else:
                        current_service['state'] = 'stopped'
            if current_service:
                services.append(current_service)
        except Exception:
            pass
        return services
    
    def start_service(self, name: str) -> bool:
        """Запустить службу"""
        try:
            cmd = f'sc start "{name}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def stop_service(self, name: str) -> bool:
        """Остановить службу"""
        try:
            cmd = f'sc stop "{name}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def delete_service(self, name: str) -> bool:
        """Удалить службу"""
        try:
            cmd = f'sc delete "{name}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def disable_service(self, name: str) -> bool:
        """Отключить службу (установить тип запуска disabled)"""
        try:
            cmd = f'sc config "{name}" start= disabled'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def enable_service(self, name: str) -> bool:
        """Включить службу (установить тип запуска auto)"""
        try:
            cmd = f'sc config "{name}" start= auto'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False


# Функции для быстрого доступа
def get_all_autoruns():
    """Получить всю автозагрузку"""
    manager = AutorunManager()
    return {
        'registry': manager.get_registry_autoruns(),
        'startup_folder': manager.get_startup_folder_items(),
        'scheduled_tasks': manager.get_scheduled_tasks()
    }


def remove_autorun(location: str, name: str) -> bool:
    """Удалить элемент автозагрузки"""
    manager = AutorunManager()
    
    if location == 'registry':
        return manager.remove_registry_autorun(name)
    elif location == 'startup':
        return manager.remove_from_startup(name)
    elif location == 'scheduler':
        return manager.delete_scheduled_task(name)
    
    return False

"""
Модуль управления автозагрузкой Windows.
Показываем только те места, куда реально прячутся вирусы.
Службы/задачи — через PowerShell/UTF-8 (корректная кириллица).
"""

import winreg
import os
import subprocess
import csv
import io
import logging

CREATE_NO_WINDOW = 0x08000000
logger = logging.getLogger(__name__)


class AutorunManager:
    """Управление всеми типами автозагрузки Windows"""

    # (location_id, hive, path, [значения] или None=все, view_flag)
    # Winlogon показан точечно: Shell, Userinit, AppSetup, Taskman — там прячутся вирусы.
    REGISTRY_LOCATIONS = [
        ('HKCU_Run',            winreg.HKEY_CURRENT_USER,  r'Software\Microsoft\Windows\CurrentVersion\Run',       None, 0),
        ('HKCU_RunOnce',        winreg.HKEY_CURRENT_USER,  r'Software\Microsoft\Windows\CurrentVersion\RunOnce',   None, 0),
        ('HKLM_Run',            winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run',       None, 0),
        ('HKLM_RunOnce',        winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce',   None, 0),
        ('HKLM_Run_WOW64',      winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run',       None, winreg.KEY_WOW64_32KEY),
        ('HKLM_RunOnce_WOW64',  winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce',   None, winreg.KEY_WOW64_32KEY),

        # Winlogon — ТОЛЬКО опасные значения
        ('Winlogon_Shell',      winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', ['Shell'],    0),
        ('Winlogon_Userinit',   winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', ['Userinit'], 0),
        ('Winlogon_AppSetup',   winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', ['AppSetup'], 0),
        ('Winlogon_Taskman',    winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', ['Taskman'],  0),
        ('Winlogon_HKCU_Shell',    winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', ['Shell'],    0),
        ('Winlogon_HKCU_Userinit', winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', ['Userinit'], 0),

        # AppInit_DLLs — инжект DLL в каждый процесс
        ('AppInit_DLLs_64',     winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', ['AppInit_DLLs'],     0),
        ('AppInit_DLLs_32',     winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', ['AppInit_DLLs'],     winreg.KEY_WOW64_32KEY),

        # Explorer Run — альтернативный автозапуск
        ('Explorer_Run_HKCU',   winreg.HKEY_CURRENT_USER,  r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',  None, 0),
        ('Explorer_Run_HKLM',   winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',  None, 0),
    ]

    # Человеко-читаемые метки
    LOCATION_LABELS = {
        'HKCU_Run': 'HKCU\\Run',
        'HKCU_RunOnce': 'HKCU\\RunOnce',
        'HKLM_Run': 'HKLM\\Run',
        'HKLM_RunOnce': 'HKLM\\RunOnce',
        'HKLM_Run_WOW64': 'HKLM\\Run (32)',
        'HKLM_RunOnce_WOW64': 'HKLM\\RunOnce (32)',
        'Winlogon_Shell': 'Winlogon\\Shell',
        'Winlogon_Userinit': 'Winlogon\\Userinit',
        'Winlogon_AppSetup': 'Winlogon\\AppSetup',
        'Winlogon_Taskman': 'Winlogon\\Taskman',
        'Winlogon_HKCU_Shell': 'Winlogon(HKCU)\\Shell',
        'Winlogon_HKCU_Userinit': 'Winlogon(HKCU)\\Userinit',
        'AppInit_DLLs_64': 'AppInit_DLLs (64)',
        'AppInit_DLLs_32': 'AppInit_DLLs (32)',
        'Explorer_Run_HKCU': 'Policies\\Explorer\\Run (HKCU)',
        'Explorer_Run_HKLM': 'Policies\\Explorer\\Run (HKLM)',
    }

    # Значения для Winlogon, которые нужно ВОССТАНОВИТЬ, а не удалять
    WINLOGON_DEFAULTS = {
        'Shell': 'explorer.exe',
        'Userinit': r'C:\Windows\system32\userinit.exe,',
    }

    def __init__(self):
        self.startup_folder = self._get_startup_folder()

    def _get_startup_folder(self) -> str:
        appdata = os.getenv('APPDATA') or os.path.expanduser(r'~\AppData\Roaming')
        return os.path.join(appdata, r'Microsoft\Windows\Start Menu\Programs\Startup')

    # ==================== РЕЕСТР ====================

    def get_registry_autoruns(self) -> list:
        """
        Все опасные записи автозагрузки.
        Returns list[dict]: {'location', 'location_label', 'name', 'value', 'is_default'}
        """
        result = []
        for loc_id, hive, path, value_filter, view_flag in self.REGISTRY_LOCATIONS:
            try:
                access = winreg.KEY_READ | view_flag
                try:
                    key = winreg.OpenKey(hive, path, 0, access)
                except OSError:
                    continue

                try:
                    if value_filter is None:
                        i = 0
                        while True:
                            try:
                                value_name, value_data, _ = winreg.EnumValue(key, i)
                                result.append({
                                    'location': loc_id,
                                    'location_label': self.LOCATION_LABELS.get(loc_id, loc_id),
                                    'name': value_name,
                                    'value': value_data,
                                    'is_default': False,
                                })
                                i += 1
                            except OSError:
                                break
                    else:
                        for vname in value_filter:
                            try:
                                value_data, _ = winreg.QueryValueEx(key, vname)
                                default = self.WINLOGON_DEFAULTS.get(vname)
                                is_default = (default is not None and value_data == default)
                                result.append({
                                    'location': loc_id,
                                    'location_label': self.LOCATION_LABELS.get(loc_id, loc_id),
                                    'name': vname,
                                    'value': value_data,
                                    'is_default': is_default,
                                })
                            except OSError:
                                pass
                finally:
                    winreg.CloseKey(key)
            except OSError:
                pass
        return result

    def _find_location(self, loc_id):
        for entry in self.REGISTRY_LOCATIONS:
            if entry[0] == loc_id:
                return entry
        return None

    def remove_registry_autorun(self, name: str, location: str) -> bool:
        """
        Удалить запись автозагрузки.
        Для Winlogon\\Shell / Userinit — ВОССТАНОВИТЬ дефолт (а не удалить).
        """
        entry = self._find_location(location)
        if not entry:
            return False
        _, hive, path, _, view_flag = entry

        # Winlogon Shell/Userinit — восстановить дефолт
        if name in self.WINLOGON_DEFAULTS and location.startswith('Winlogon_'):
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE | view_flag)
                try:
                    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, self.WINLOGON_DEFAULTS[name])
                    return True
                finally:
                    winreg.CloseKey(key)
            except OSError as e:
                logger.error(f"Не удалось восстановить Winlogon\\{name}: {e}")
                return False

        # Обычное удаление
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE | view_flag)
            try:
                winreg.DeleteValue(key, name)
                return True
            finally:
                winreg.CloseKey(key)
        except OSError as e:
            logger.error(f"Не удалось удалить {location}\\{name}: {e}")
            return False

    def add_registry_autorun(self, name: str, path: str, location: str = 'HKCU_Run') -> bool:
        entry = self._find_location(location)
        if not entry:
            return False
        _, hive, key_path, _, view_flag = entry
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE | view_flag)
            try:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, f'"{path}"')
                return True
            finally:
                winreg.CloseKey(key)
        except OSError:
            return False

    # ==================== ПАПКА АВТОЗАГРУЗКИ ====================

    def get_startup_folder_items(self) -> list:
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
        try:
            shortcut_path = os.path.join(self.startup_folder, f'{name}.lnk')
            ps_command = f'''
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WScriptShell.CreateShortcut("{shortcut_path}")
            $Shortcut.TargetPath = "{target_path}"
            $Shortcut.Save()
            '''
            subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                creationflags=CREATE_NO_WINDOW
            )
            return True
        except Exception:
            return False

    def remove_from_startup(self, filename: str) -> bool:
        try:
            filepath = os.path.join(self.startup_folder, filename)
            if os.path.exists(filepath):
                os.remove(filepath)
            return True
        except Exception:
            return False

    # ==================== ПЛАНИРОВЩИК ЗАДАЧ ====================

    def get_scheduled_tasks(self) -> list:
        """Список задач. chcp 65001 для корректной кириллицы."""
        tasks = []
        try:
            result = subprocess.run(
                'chcp 65001 > nul && schtasks /query /fo CSV /nh',
                shell=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                creationflags=CREATE_NO_WINDOW
            )
            reader = csv.reader(io.StringIO(result.stdout))
            rows = list(reader)
            for row in rows:
                if len(row) >= 1:
                    task_name = row[0].strip().lstrip('\ufeff')
                    if task_name:
                        tasks.append({'name': task_name})
        except Exception as e:
            logger.error(f"Ошибка получения задач планировщика: {e}")
        return tasks

    def create_scheduled_task(self, name: str, program: str, trigger: str = 'onlogon') -> bool:
        try:
            cmd = f'schtasks /create /tn "{name}" /tr "{program}" /sc {trigger} /rl highest /f'
            return subprocess.run(cmd, shell=True, capture_output=True).returncode == 0
        except Exception:
            return False

    def delete_scheduled_task(self, name: str) -> bool:
        try:
            cmd = f'schtasks /delete /tn "{name}" /f'
            return subprocess.run(cmd, shell=True, capture_output=True).returncode == 0
        except Exception:
            return False

    def disable_scheduled_task(self, name: str) -> bool:
        try:
            cmd = f'schtasks /change /tn "{name}" /disable'
            return subprocess.run(cmd, shell=True, capture_output=True).returncode == 0
        except Exception:
            return False

    def enable_scheduled_task(self, name: str) -> bool:
        try:
            cmd = f'schtasks /change /tn "{name}" /enable'
            return subprocess.run(cmd, shell=True, capture_output=True).returncode == 0
        except Exception:
            return False

    # ==================== СЛУЖБЫ (через PowerShell) ====================

    def get_services(self) -> list:
        """Список служб. PowerShell + UTF-8 — корректная кириллица."""
        services = []
        try:
            ps = (
                '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; '
                'Get-Service | Select-Object Name,DisplayName,Status | '
                'ConvertTo-Csv -NoTypeInformation'
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps],
                capture_output=True,
                text=True,
                encoding='utf-8-sig',
                errors='replace',
                creationflags=CREATE_NO_WINDOW
            )
            reader = csv.reader(io.StringIO(result.stdout))
            rows = list(reader)
            for row in rows[1:]:  # пропускаем заголовок
                if len(row) >= 3:
                    services.append({
                        'name': row[0].strip(),
                        'display_name': row[1].strip(),
                        'state': row[2].strip().lower(),
                    })
        except Exception as e:
            logger.error(f"Ошибка получения служб: {e}")
        return services

    def start_service(self, name: str) -> bool:
        try:
            return subprocess.run(
                ['sc', 'start', name],
                capture_output=True,
                creationflags=CREATE_NO_WINDOW
            ).returncode == 0
        except Exception:
            return False

    def stop_service(self, name: str) -> bool:
        try:
            return subprocess.run(
                ['sc', 'stop', name],
                capture_output=True,
                creationflags=CREATE_NO_WINDOW
            ).returncode == 0
        except Exception:
            return False

    def delete_service(self, name: str) -> bool:
        try:
            return subprocess.run(
                ['sc', 'delete', name],
                capture_output=True,
                creationflags=CREATE_NO_WINDOW
            ).returncode == 0
        except Exception:
            return False

    def disable_service(self, name: str) -> bool:
        try:
            return subprocess.run(
                ['sc', 'config', name, 'start=', 'disabled'],
                capture_output=True,
                creationflags=CREATE_NO_WINDOW
            ).returncode == 0
        except Exception:
            return False

    def enable_service(self, name: str) -> bool:
        try:
            return subprocess.run(
                ['sc', 'config', name, 'start=', 'auto'],
                capture_output=True,
                creationflags=CREATE_NO_WINDOW
            ).returncode == 0
        except Exception:
            return False


# Функции быстрого доступа
def get_all_autoruns():
    manager = AutorunManager()
    return {
        'registry': manager.get_registry_autoruns(),
        'startup_folder': manager.get_startup_folder_items(),
        'scheduled_tasks': manager.get_scheduled_tasks()
    }


def remove_autorun(location: str, name: str) -> bool:
    manager = AutorunManager()
    if location == 'registry':
        return manager.remove_registry_autorun(name, 'HKCU_Run')
    elif location == 'startup':
        return manager.remove_from_startup(name)
    elif location == 'scheduler':
        return manager.delete_scheduled_task(name)
    return False
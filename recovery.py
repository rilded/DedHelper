"""
Модуль восстановления Windows Recovery Environment (WinRE)
Создание, восстановление и управление средой восстановления
"""

import subprocess
import os
import shutil
import ctypes


class WinREManager:
    """Класс для управления средой восстановления Windows"""
    
    def __init__(self):
        self.is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        self.windows_dir = os.environ.get('SYSTEMROOT', r'C:\Windows')
        self.system32_dir = os.path.join(self.windows_dir, 'System32')
    
    def get_winre_status(self) -> dict:
        """Получить статус WinRE"""
        result = {
            'enabled': False,
            'path': '',
            'guid': ''
        }
        
        try:
            # Проверяем статус через reagentc
            cmd_result = subprocess.run(
                ['reagentc', '/info'],
                capture_output=True,
                text=True,
                encoding='cp866'
            )
            
            output = cmd_result.stdout
            
            if 'Включено' in output or 'Enabled' in output:
                result['enabled'] = True
            
            # Извлекаем путь
            for line in output.split('\n'):
                if 'Расположение' in line or 'Location' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        result['path'] = parts[1].strip()
            
            # Получаем GUID загрузочкой записи
            cmd_result = subprocess.run(
                ['bcdedit', '/enum', 'all'],
                capture_output=True,
                text=True,
                encoding='cp866'
            )
            
            for line in cmd_result.stdout.split('\n'):
                if 'winre' in line.lower() or 'recovery' in line.lower():
                    # Предыдущая строка должна содержать идентификатор
                    idx = list(cmd_result.stdout.split('\n')).index(line)
                    if idx > 0:
                        prev_line = list(cmd_result.stdout.split('\n'))[idx - 1]
                        if '{' in prev_line:
                            result['guid'] = prev_line.split('{')[1].split('}')[0]
            
        except Exception:
            pass
        
        return result
    
    def enable_winre(self) -> bool:
        """Включить WinRE"""
        try:
            cmd = 'reagentc /enable'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def disable_winre(self) -> bool:
        """Отключить WinRE"""
        try:
            cmd = 'reagentc /disable'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def set_winre_path(self, path: str) -> bool:
        """Установить путь к WinRE"""
        try:
            # Сначала отключаем
            self.disable_winre()
            
            # Устанавливаем новый путь
            cmd = f'reagentc /setreimage /path "{path}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Включаем обратно
            if result.returncode == 0:
                self.enable_winre()
            
            return result.returncode == 0
        except Exception:
            return False
    
    def create_winre_backup(self, backup_path: str) -> bool:
        """Создать резервную копию WinRE"""
        try:
            # Находим текущий образ WinRE (winre.wim)
            winre_paths = [
                r'C:\Windows\System32\Recovery\winre.wim',
                r'C:\Recovery\Windows\winre.wim',
            ]
            
            source_path = None
            for path in winre_paths:
                if os.path.exists(path):
                    source_path = path
                    break
            
            if source_path:
                # Копируем файл
                os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                shutil.copy2(source_path, backup_path)
                return True
            
            return False
        except Exception:
            return False
    
    def restore_winre_from_backup(self, backup_path: str) -> bool:
        """Восстановить WinRE из резервной копии"""
        try:
            if not os.path.exists(backup_path):
                return False
            
            # Целевые пути для восстановления
            target_paths = [
                r'C:\Windows\System32\Recovery\winre.wim',
                r'C:\Recovery\Windows\winre.wim',
            ]
            
            # Отключаем WinRE перед заменой
            self.disable_winre()
            
            # Копируем в каждый существующий путь
            for target_path in target_paths:
                try:
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    shutil.copy2(backup_path, target_path)
                except Exception:
                    pass
            
            # Включаем WinRE
            self.enable_winre()
            return True
        except Exception:
            return False
    
    def rebuild_winre(self) -> bool:
        """Пересоздать WinRE из системных файлов"""
        try:
            # Отключаем текущий WinRE
            self.disable_winre()
            
            # Копируем winre.wim из установочных файлов
            sources = [
                r'C:\Windows\WinSxS\winre.wim',
                r'C:\$WINDOWS.~BT\Sources\SafeOS\winre.wim',
            ]
            
            targets = [
                r'C:\Windows\System32\Recovery\winre.wim',
                r'C:\Recovery\Windows\winre.wim',
            ]
            
            for source in sources:
                if os.path.exists(source):
                    for target in targets:
                        try:
                            os.makedirs(os.path.dirname(target), exist_ok=True)
                            shutil.copy2(source, target)
                            break
                        except Exception:
                            pass
                    break
            
            # Включаем WinRE
            return self.enable_winre()
        except Exception:
            return False
    
    def boot_to_winre(self) -> bool:
        """Загрузиться в WinRE (перезагрузка)"""
        try:
            # Используем shutdown для загрузки в WinRE
            cmd = 'shutdown /r /o /t 5'
            subprocess.run(cmd, shell=True)
            return True
        except Exception:
            return False
    
    def create_recovery_drive(self, drive_letter: str) -> bool:
        """Создать диск восстановления на указанном диске"""
        try:
            # Используем recdisc для создания диска восстановления
            cmd = f'recdisc /drive {drive_letter}: /quiet'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def check_recovery_partition(self) -> dict:
        """Проверить раздел восстановления"""
        result = {
            'exists': False,
            'size_mb': 0,
            'drive_letter': ''
        }
        
        try:
            # Получаем информацию о разделах через diskpart
            ps_command = '''
            Get-Partition | Where-Object {$_.Type -eq "Recovery"} | Select-Object DriveLetter, Size
            '''
            cmd_result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True
            )
            
            output = cmd_result.stdout.strip()
            if output:
                result['exists'] = True
                # Парсим вывод PowerShell
                for line in output.split('\n')[2:]:  # Пропускаем заголовок
                    parts = line.split()
                    if len(parts) >= 2:
                        result['drive_letter'] = parts[0]
                        try:
                            size_bytes = int(parts[1])
                            result['size_mb'] = size_bytes // (1024 * 1024)
                        except ValueError:
                            pass
                        break
        except Exception:
            pass
        
        return result
    
    def mount_winre(self, mount_path: str) -> bool:
        """Смонтировать образ WinRE для редактирования"""
        try:
            # Находим winre.wim
            winre_path = r'C:\Windows\System32\Recovery\winre.wim'
            if not os.path.exists(winre_path):
                return False
            
            # Монтируем через DISM
            cmd = f'dism /Mount-Image /ImageFile:"{winre_path}" /Index:1 /MountDir:"{mount_path}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def unmount_winre(self, mount_path: str, save: bool = True) -> bool:
        """Размонтировать образ WinRE"""
        try:
            if save:
                cmd = f'dism /Unmount-Image /MountDir:"{mount_path}" /Commit'
            else:
                cmd = f'dism /Unmount-Image /MountDir:"{mount_path}" /Discard'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False


# Функции для быстрого доступа
def get_winre_status():
    """Получить статус WinRE"""
    manager = WinREManager()
    return manager.get_winre_status()


def enable_winre():
    """Включить WinRE"""
    manager = WinREManager()
    return manager.enable_winre()


def disable_winre():
    """Отключить WinRE"""
    manager = WinREManager()
    return manager.disable_winre()


def boot_to_winre():
    """Загрузиться в WinRE"""
    manager = WinREManager()
    return manager.boot_to_winre()

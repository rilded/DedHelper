"""
Модуль снятия ограничений Windows
ScancodeMap, Debuggers, DisallowRun, Hosts файл
"""

import winreg
import os
import subprocess
import shutil
import ctypes
import logging

logger = logging.getLogger(__name__)


def run_hidden_powershell(ps_command: str, capture_output: bool = True) -> subprocess.CompletedProcess:
    """Выполнить PowerShell команду без показа окна"""
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    return subprocess.run(
        ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
        capture_output=capture_output,
        text=True,
        startupinfo=startupinfo
    )


class RestrictionsManager:
    """Класс для снятия различных ограничений Windows"""

    # Пути к ключам реестра для ограничений - РАСШИРЕННЫЙ СПИСОК
    RESTRICTION_KEYS = {
        'ScancodeMap': (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Keyboard Layout'),
        'ScancodeMap_WOW64': (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Keyboard Layout'),
        'Debuggers': (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'),
        'Debuggers_WOW64': (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'),
        'DisallowRun': (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'),
        'DisallowRun_LocalMachine': (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'),
        'ExplorerRestrictions': (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'),
        'SystemRestrictions': (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'),
    }

    HOSTS_PATH = r'C:\Windows\System32\drivers\etc\hosts'

    def __init__(self):
        self.is_admin = ctypes.windll.shell32.IsUserAnAdmin()

    # ==================== SCANDODEMAP ====================

    def get_scancode_map(self) -> bytes:
        """Получить текущий ScancodeMap из всех возможных мест"""
        # Проверяем основное местоположение
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SYSTEM\CurrentControlSet\Control\Keyboard Layout',
                0,
                winreg.KEY_READ
            )
            try:
                value, _ = winreg.QueryValueEx(key, 'Scancode Map')
                winreg.CloseKey(key)
                return value
            except OSError:
                pass
            winreg.CloseKey(key)
        except OSError:
            pass
        
        # Проверяем WOW64 ключ
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SYSTEM\CurrentControlSet\Control\Keyboard Layout',
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            )
            try:
                value, _ = winreg.QueryValueEx(key, 'Scancode Map')
                winreg.CloseKey(key)
                return value
            except OSError:
                pass
            winreg.CloseKey(key)
        except OSError:
            pass
            
        return None
    
    def remove_scancode_map(self) -> bool:
        """Удалить ScancodeMap (сбросить переназначение клавиш)"""
        try:
            # Сначала берём ownership через PowerShell
            ps_script = '''
            $ErrorActionPreference = "SilentlyContinue"
            $keyPath = "SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout"
            $fullPath = "HKLM:\\$keyPath"
            
            try {
                # Берём ownership
                $acl = Get-Acl $fullPath
                $adminAccount = New-Object System.Security.Principal.NTAccount("Administrators")
                $acl.SetOwner($adminAccount)
                Set-Acl $fullPath -AclObject $acl
                
                # Даём полные права
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    $adminAccount,
                    "FullControl",
                    "Allow"
                )
                $acl.ResetAccessRule($rule)
                Set-Acl $fullPath -AclObject $acl
            } catch {}
            '''
            run_hidden_powershell(ps_script)
            
            # Теперь удаляем ключ
            hive, path = self.RESTRICTION_KEYS['ScancodeMap']
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
            try:
                winreg.DeleteValue(key, 'Scancode Map')
                winreg.CloseKey(key)
                return True
            except OSError:
                pass
            winreg.CloseKey(key)
            
            # Пробуем через reg delete
            subprocess.run(['reg', 'delete', r'HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout', '/v', 'Scancode Map', '/f'], 
                          capture_output=True)
            return True
            
        except Exception as e:
            logger.error(f"Ошибка удаления ScancodeMap: {e}")
            return False
    
    def set_scancode_map(self, mapping: dict) -> bool:
        """
        Установить ScancodeMap для переназначения клавиш
        mapping: dict вида {исходный_сканкод: целевой_сканкод}
        """
        try:
            # Формат ScancodeMap:
            # 4 байта версия, 4 байта флаги, 4 байта количество маппингов,
            # затем маппинги (по 8 байт каждый), 4 байта null terminator
            num_mappings = len(mapping)
            data_size = 4 + 4 + 4 + (num_mappings * 8) + 4
            
            # Создаём байтовый массив
            data = bytearray(data_size)
            
            # Версия (0)
            data[0:4] = (0).to_bytes(4, 'little')
            # Флаги (0)
            data[4:8] = (0).to_bytes(4, 'little')
            # Количество маппингов
            data[8:12] = (num_mappings).to_bytes(4, 'little')
            
            # Маппинги
            offset = 12
            for from_code, to_code in mapping.items():
                data[offset:offset+4] = (to_code).to_bytes(4, 'little')
                data[offset+4:offset+8] = (from_code).to_bytes(4, 'little')
                offset += 8
            
            # Null terminator
            data[offset:offset+4] = (0).to_bytes(4, 'little')
            
            hive, path = self.RESTRICTION_KEYS['ScancodeMap']
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, 'Scancode Map', 0, winreg.REG_BINARY, bytes(data))
            winreg.CloseKey(key)
            return True
        except Exception:
            return False
    
    # ==================== DEBUGGERS (IFEO) ====================
    
    def get_debuggers_list(self) -> list:
        """Получить список приложений с подменой через IFEO"""
        result = []
        try:
            hive, path = self.RESTRICTION_KEYS['Debuggers']
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            
            i = 0
            while True:
                try:
                    app_name = winreg.EnumKey(key, i)
                    app_key_path = f"{path}\\{app_name}"
                    app_key = winreg.OpenKey(hive, app_key_path, 0, winreg.KEY_READ)
                    try:
                        debugger_value, _ = winreg.QueryValueEx(app_key, 'Debugger')
                        result.append({
                            'application': app_name,
                            'debugger': debugger_value
                        })
                    except OSError:
                        pass
                    winreg.CloseKey(app_key)
                    i += 1
                except OSError:
                    break
            
            winreg.CloseKey(key)
        except OSError:
            pass
        
        return result
    
    def remove_debugger(self, application: str) -> bool:
        """Удалить подмену приложения через IFEO"""
        try:
            hive, path = self.RESTRICTION_KEYS['Debuggers']
            app_key_path = f"{path}\\{application}"
            app_key = winreg.OpenKey(hive, app_key_path, 0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(app_key, 'Debugger')
                winreg.CloseKey(app_key)
                
                # Если ключ пустой, удаляем весь ключ приложения
                try:
                    winreg.DeleteKey(hive, app_key_path)
                except OSError:
                    pass
                
                return True
            except OSError:
                winreg.CloseKey(app_key)
                return False
        except OSError:
            return False
    
    def remove_all_debuggers(self) -> int:
        """Удалить все подмены приложений через IFEO"""
        count = 0
        debuggers = self.get_debuggers_list()
        for debugger in debuggers:
            if self.remove_debugger(debugger['application']):
                count += 1
        return count
    
    # ==================== DISALLOWRUN ====================
    
    def get_disallow_run(self) -> list:
        """Получить список запрещённых программ"""
        result = []
        try:
            hive, path = self.RESTRICTION_KEYS['DisallowRun']
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            
            # Проверяем, включено ли ограничение
            try:
                disallow_run, _ = winreg.QueryValueEx(key, 'DisallowRun')
                if disallow_run == 1:
                    # Читаем список запрещенных программ
                    i = 0
                    while True:
                        try:
                            value_name = f'{i}'
                            program, _ = winreg.QueryValueEx(key, value_name)
                            result.append(program)
                            i += 1
                        except OSError:
                            break
            except OSError:
                pass
            
            winreg.CloseKey(key)
        except OSError:
            pass
        
        return result
    
    def remove_disallow_run(self) -> bool:
        """Удалить ограничение на запуск программ"""
        try:
            hive, path = self.RESTRICTION_KEYS['DisallowRun']
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
            
            # Удаляем флаг ограничения
            try:
                winreg.DeleteValue(key, 'DisallowRun')
            except OSError:
                pass
            
            # Удаляем все записи запрещённых программ
            i = 0
            while True:
                try:
                    winreg.DeleteValue(key, f'{i}')
                    i += 1
                except OSError:
                    break
            
            winreg.CloseKey(key)
            return True
        except OSError:
            return False
    
    # ==================== HOSTS ФАЙЛ ====================
    
    def get_hosts_content(self) -> str:
        """Получить содержимое hosts файла"""
        try:
            with open(self.HOSTS_PATH, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            try:
                with open(self.HOSTS_PATH, 'r', encoding='cp1251') as f:
                    return f.read()
            except Exception:
                return "Не удалось прочитать файл"
    
    def backup_hosts(self) -> bool:
        """Создать резервную копию hosts файла"""
        try:
            backup_path = self.HOSTS_PATH + '.backup'
            shutil.copy2(self.HOSTS_PATH, backup_path)
            return True
        except Exception:
            return False
    
    def restore_hosts_default(self) -> bool:
        """Восстановить hosts файл по умолчанию"""
        default_hosts = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1     localhost
"""
        try:
            # Сначала берём ownership
            subprocess.run(['takeown', '/f', self.HOSTS_PATH], capture_output=True)
            subprocess.run(['icacls', self.HOSTS_PATH, '/grant', 'Administrators:F'], capture_output=True)
            
            with open(self.HOSTS_PATH, 'w', encoding='utf-8') as f:
                f.write(default_hosts)
            return True
        except Exception:
            return False
    
    def clean_hosts(self) -> bool:
        """Очистить hosts файл от сторонних записей (оставить только комментарии)"""
        try:
            content = self.get_hosts_content()
            lines = content.split('\n')
            clean_lines = []
            
            for line in lines:
                stripped = line.strip()
                # Оставляем только комментарии и пустые строки
                if stripped.startswith('#') or stripped == '':
                    clean_lines.append(line)
                # Также оставляем localhost
                elif '127.0.0.1' in stripped or '::1' in stripped:
                    if 'localhost' in stripped:
                        clean_lines.append(line)
            
            # Берём ownership
            subprocess.run(['takeown', '/f', self.HOSTS_PATH], capture_output=True)
            subprocess.run(['icacls', self.HOSTS_PATH, '/grant', 'Administrators:F'], capture_output=True)
            
            with open(self.HOSTS_PATH, 'w', encoding='utf-8') as f:
                f.write('\n'.join(clean_lines))
            return True
        except Exception:
            return False
    
    def add_hosts_entry(self, ip: str, hostname: str) -> bool:
        """Добавить запись в hosts файл"""
        try:
            subprocess.run(['takeown', '/f', self.HOSTS_PATH], capture_output=True)
            subprocess.run(['icacls', self.HOSTS_PATH, '/grant', 'Administrators:F'], capture_output=True)
            
            with open(self.HOSTS_PATH, 'a', encoding='utf-8') as f:
                f.write(f'\n{ip}\t{hostname}\n')
            return True
        except Exception:
            return False
    
    def remove_hosts_entry(self, hostname: str) -> bool:
        """Удалить запись из hosts файла"""
        try:
            content = self.get_hosts_content()
            lines = content.split('\n')
            new_lines = []
            
            for line in lines:
                if hostname not in line:
                    new_lines.append(line)
            
            subprocess.run(['takeown', '/f', self.HOSTS_PATH], capture_output=True)
            subprocess.run(['icacls', self.HOSTS_PATH, '/grant', 'Administrators:F'], capture_output=True)
            
            with open(self.HOSTS_PATH, 'w', encoding='utf-8') as f:
                f.write('\n'.join(new_lines))
            return True
        except Exception:
            return False
    
    # ==================== ОБЩИЕ ОГРАНИЧЕНИЯ ====================

    def get_all_restrictions(self) -> dict:
        """Получить все активные ограничения"""
        return {
            'scancode_map': self.get_scancode_map() is not None,
            'debuggers': self.get_debuggers_list(),
            'disallow_run': self.get_disallow_run(),
            'hosts_content': self.get_hosts_content()
        }

    def remove_group_policies(self) -> int:
        """Удалить политики Group Policy"""
        count = 0
        policy_paths = [
            (winreg.HKEY_CURRENT_USER, r'Software\Policies\Microsoft\Windows'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows'),
        ]

        for hive, base_path in policy_paths:
            try:
                # Удаляем все подразделы в Policies\Microsoft\Windows
                self._delete_key_tree(hive, base_path)
                count += 1
            except Exception:
                pass

        return count

    def _delete_key_tree(self, hive, key_path):
        """Рекурсивно удалить все подразделы ключа"""
        try:
            # Сначала получаем все подразделы
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_ALL_ACCESS)
            subkeys = []
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkeys.append(subkey_name)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)

            # Рекурсивно удаляем подразделы
            for subkey in subkeys:
                subkey_path = f"{key_path}\\{subkey}"
                self._delete_key_tree(hive, subkey_path)

            # Теперь удаляем содержимое текущего ключа
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_ALL_ACCESS)
                values = []
                i = 0
                while True:
                    try:
                        value_name, _, _ = winreg.EnumValue(key, i)
                        values.append(value_name)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)

                # Удаляем все значения
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
                for value_name in values:
                    try:
                        winreg.DeleteValue(key, value_name)
                    except OSError:
                        pass
                winreg.CloseKey(key)
            except Exception:
                pass

        except Exception:
            pass

    def remove_all_restrictions(self) -> dict:
        """Удалить все ограничения"""
        result = {
            'scancode_map': False,
            'debuggers': 0,
            'disallow_run': False,
            'hosts': False,
            'group_policy': 0
        }

        if self.remove_scancode_map():
            result['scancode_map'] = True

        result['debuggers'] = self.remove_all_debuggers()

        if self.remove_disallow_run():
            result['disallow_run'] = True

        if self.clean_hosts():
            result['hosts'] = True

        # Удаляем Group Policy
        result['group_policy'] = self.remove_group_policies()
        
        if self.remove_disallow_run():
            result['disallow_run'] = True
        
        if self.clean_hosts():
            result['hosts'] = True
        
        return result


# Функции для быстрого доступа
def get_restrictions():
    """Получить все ограничения"""
    manager = RestrictionsManager()
    return manager.get_all_restrictions()


def remove_all_restrictions():
    """Удалить все ограничения"""
    manager = RestrictionsManager()
    return manager.remove_all_restrictions()

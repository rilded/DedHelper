"""
Модуль снятия ограничений Windows
ScancodeMap, IFEO, DisallowRun, Group Policy, Winlogon, AppInit, SafeBoot, SpecialAccounts
"""

import winreg
import subprocess
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

    RESTRICTION_KEYS = {
        'ScancodeMap': (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Keyboard Layout'),
        'Debuggers': (winreg.HKEY_LOCAL_MACHINE,
                      r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'),
        'Debuggers_WOW64': (winreg.HKEY_LOCAL_MACHINE,
                            r'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'),
        'DisallowRun': (winreg.HKEY_CURRENT_USER,
                        r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'),
        'DisallowRun_LocalMachine': (winreg.HKEY_LOCAL_MACHINE,
                                     r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'),
    }

    # Ветки Policies, которые нужно полностью удалить (там сидит большинство вирусных блокировок:
    # DisableTaskMgr, DisableRegistryTools, DisableCMD, NoRun, NoFind, NoFolderOptions, NoControlPanel,
    # NoViewContextMenu, NoTrayContextMenu, NoDrives, NoViewOnDrive, NoDriveTypeAutoRun, NoSetTaskbar,
    # HidePowerOptions, NoLogoff, NoClose, NoChangeWallPaper, NoViewOnDrive и т.д.)
    POLICY_PATHS = [
        (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Policies'),
        (winreg.HKEY_CURRENT_USER, r'Software\Policies\Microsoft\Windows'),
        (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'),
        (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows'),
        (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies'),
        (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Policies\Microsoft\Windows'),
    ]

    # Winlogon — куда вирусы прописывают свою оболочку/загрузчик
    WINLOGON_DEFAULTS = {
        'Shell': 'explorer.exe',
        'Userinit': r'C:\Windows\system32\userinit.exe,',
    }

    def __init__(self):
        self.is_admin = ctypes.windll.shell32.IsUserAnAdmin()

    # ==================== SCANCODE MAP ====================

    def get_scancode_map(self) -> bytes:
        """Получить текущий ScancodeMap"""
        for view_flag in (0, winreg.KEY_WOW64_64KEY):
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Keyboard Layout',
                    0,
                    winreg.KEY_READ | view_flag
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
            ps_script = '''
            $ErrorActionPreference = "SilentlyContinue"
            $keyPath = "SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout"
            $fullPath = "HKLM:\\$keyPath"
            try {
                $acl = Get-Acl $fullPath
                $adminAccount = New-Object System.Security.Principal.NTAccount("Administrators")
                $acl.SetOwner($adminAccount)
                Set-Acl $fullPath -AclObject $acl
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    $adminAccount, "FullControl", "Allow"
                )
                $acl.ResetAccessRule($rule)
                Set-Acl $fullPath -AclObject $acl
            } catch {}
            '''
            run_hidden_powershell(ps_script)

            hive, path = self.RESTRICTION_KEYS['ScancodeMap']
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
            try:
                winreg.DeleteValue(key, 'Scancode Map')
                winreg.CloseKey(key)
                return True
            except OSError:
                pass
            winreg.CloseKey(key)

            subprocess.run(
                ['reg', 'delete', r'HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout',
                 '/v', 'Scancode Map', '/f'],
                capture_output=True
            )
            return True
        except Exception as e:
            logger.error(f"Ошибка удаления ScancodeMap: {e}")
            return False

    # ==================== IFEO (Debugger + GlobalFlag) ====================

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
                        result.append({'application': app_name, 'debugger': debugger_value})
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
        """Удалить все подмены приложений через IFEO (Debugger)"""
        count = 0
        for debugger in self.get_debuggers_list():
            if self.remove_debugger(debugger['application']):
                count += 1
        return count

    def remove_ifeo_global_flags(self) -> int:
        """Удалить GlobalFlag из всех записей IFEO (используется для Silent Process Exit)"""
        count = 0
        for key_name in ('Debuggers', 'Debuggers_WOW64'):
            hive, path = self.RESTRICTION_KEYS[key_name]
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            except OSError:
                continue

            subkeys = []
            try:
                i = 0
                while True:
                    try:
                        subkeys.append(winreg.EnumKey(key, i))
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(key)

            for subkey in subkeys:
                subpath = f"{path}\\{subkey}"
                try:
                    skey = winreg.OpenKey(hive, subpath, 0, winreg.KEY_SET_VALUE)
                    try:
                        winreg.DeleteValue(skey, 'GlobalFlag')
                        count += 1
                    except OSError:
                        pass
                    winreg.CloseKey(skey)
                except OSError:
                    pass
        return count

    # ==================== DISALLOWRUN ====================

    def get_disallow_run(self) -> list:
        """Получить список запрещённых программ"""
        result = []
        try:
            hive, path = self.RESTRICTION_KEYS['DisallowRun']
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            try:
                disallow_run, _ = winreg.QueryValueEx(key, 'DisallowRun')
                if disallow_run == 1:
                    i = 0
                    while True:
                        try:
                            program, _ = winreg.QueryValueEx(key, f'{i}')
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
        removed_any = False
        for key_name in ('DisallowRun', 'DisallowRun_LocalMachine'):
            hive, path = self.RESTRICTION_KEYS[key_name]
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
            except OSError:
                continue

            try:
                try:
                    winreg.DeleteValue(key, 'DisallowRun')
                    removed_any = True
                except OSError:
                    pass

                i = 0
                while True:
                    try:
                        winreg.DeleteValue(key, f'{i}')
                        removed_any = True
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(key)

            # Удаляем подключ DisallowRun если он есть
            try:
                winreg.DeleteKey(hive, f"{path}\\DisallowRun")
                removed_any = True
            except OSError:
                pass

        return removed_any

    # ==================== WINLOGON (Shell / Userinit) ====================

    def restore_winlogon_defaults(self) -> dict:
        """Восстановить Shell и Userinit в Winlogon (там часто прячутся вирусы)"""
        result = {'shell_fixed': False, 'userinit_fixed': False}
        path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_ALL_ACCESS)
        except OSError:
            return result

        try:
            for value_name, default_value in self.WINLOGON_DEFAULTS.items():
                try:
                    current, _ = winreg.QueryValueEx(key, value_name)
                    if current != default_value:
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, default_value)
                        if value_name == 'Shell':
                            result['shell_fixed'] = True
                        elif value_name == 'Userinit':
                            result['userinit_fixed'] = True
                        logger.info(f"Winlogon\\{value_name} восстановлен: {current!r} -> {default_value!r}")
                except FileNotFoundError:
                    # Значения нет — оно и так дефолтное
                    pass
                except OSError:
                    pass
        finally:
            winreg.CloseKey(key)

        return result

    # ==================== APPINIT_DLLS ====================

    def clear_appinit_dlls(self) -> bool:
        """Очистить AppInit_DLLs (классический способ инжекта вирусов в каждый процесс)"""
        path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        cleared = False

        for view_flag in (0, winreg.KEY_WOW64_64KEY):
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, path, 0,
                    winreg.KEY_SET_VALUE | view_flag
                )
            except OSError:
                continue

            try:
                try:
                    current, _ = winreg.QueryValueEx(key, 'AppInit_DLLs')
                    if current and current.strip():
                        winreg.SetValueEx(key, 'AppInit_DLLs', 0, winreg.REG_SZ, '')
                        cleared = True
                except OSError:
                    pass
                try:
                    winreg.SetValueEx(key, 'LoadAppInit_DLLs', 0, winreg.REG_DWORD, 0)
                except OSError:
                    pass
            finally:
                winreg.CloseKey(key)

        return cleared

    # ==================== SAFEBOOT ====================

    def remove_safeboot_alternate_shell(self) -> bool:
        """Удалить AlternateShell из SafeBoot (вирусы используют для подмены оболочки в Safe Mode)"""
        path = r'SYSTEM\CurrentControlSet\Control\SafeBoot'
        removed = False
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(key, 'AlternateShell')
                removed = True
            except OSError:
                pass
            winreg.CloseKey(key)
        except OSError:
            pass
        return removed

    # ==================== SPECIAL ACCOUNTS ====================

    def clear_special_accounts_userlist(self) -> bool:
        """Очистить SpecialAccounts\\UserList (скрытые учётные записи, созданные вирусом)"""
        path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_ALL_ACCESS)
        except OSError:
            return False  # Ключа нет — и хорошо

        try:
            values = []
            i = 0
            while True:
                try:
                    name, _, _ = winreg.EnumValue(key, i)
                    values.append(name)
                    i += 1
                except OSError:
                    break

            for v in values:
                try:
                    winreg.DeleteValue(key, v)
                except OSError:
                    pass
        finally:
            winreg.CloseKey(key)

        return True

    # ==================== GROUP POLICY (Policies) ====================

    def remove_group_policies(self) -> int:
        """Удалить все ветки Policies (там сидит 95% вирусных ограничений)"""
        count = 0
        for hive, path in self.POLICY_PATHS:
            if self._delete_key_tree(hive, path):
                count += 1
        return count

    def _delete_key_tree(self, hive, key_path) -> bool:
        """Рекурсивно удалить ключ и все его подразделы"""
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        except OSError:
            return False

        subkeys = []
        try:
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)

        for subkey in subkeys:
            self._delete_key_tree(hive, f"{key_path}\\{subkey}")

        try:
            parent_path, key_name = key_path.rsplit('\\', 1)
        except ValueError:
            return False

        try:
            parent = winreg.OpenKey(hive, parent_path, 0, winreg.KEY_ALL_ACCESS)
        except OSError:
            return False

        try:
            winreg.DeleteKey(parent, key_name)
            return True
        except OSError:
            return False
        finally:
            winreg.CloseKey(parent)

    # ==================== ОБЩЕЕ СНЯТИЕ ВСЕХ ОГРАНИЧЕНИЙ ====================

    def remove_all_restrictions(self) -> dict:
        """
        Удалить ВСЕ известные типы ограничений.
        HOSTS-файл НЕ трогается (по требованию).
        """
        result = {
            'scancode_map': False,
            'debuggers': 0,
            'ifeo_global_flags': 0,
            'disallow_run': False,
            'group_policy': 0,
            'winlogon_shell': False,
            'winlogon_userinit': False,
            'appinit': False,
            'safeboot': False,
            'special_accounts': False,
        }

        try:
            if self.remove_scancode_map():
                result['scancode_map'] = True
        except Exception as e:
            logger.error(f"ScancodeMap: {e}")

        try:
            result['debuggers'] = self.remove_all_debuggers()
        except Exception as e:
            logger.error(f"Debuggers: {e}")

        try:
            result['ifeo_global_flags'] = self.remove_ifeo_global_flags()
        except Exception as e:
            logger.error(f"IFEO GlobalFlag: {e}")

        try:
            if self.remove_disallow_run():
                result['disallow_run'] = True
        except Exception as e:
            logger.error(f"DisallowRun: {e}")

        try:
            result['group_policy'] = self.remove_group_policies()
        except Exception as e:
            logger.error(f"Group Policy: {e}")

        try:
            wl = self.restore_winlogon_defaults()
            result['winlogon_shell'] = wl['shell_fixed']
            result['winlogon_userinit'] = wl['userinit_fixed']
        except Exception as e:
            logger.error(f"Winlogon: {e}")

        try:
            result['appinit'] = self.clear_appinit_dlls()
        except Exception as e:
            logger.error(f"AppInit: {e}")

        try:
            result['safeboot'] = self.remove_safeboot_alternate_shell()
        except Exception as e:
            logger.error(f"SafeBoot: {e}")

        try:
            result['special_accounts'] = self.clear_special_accounts_userlist()
        except Exception as e:
            logger.error(f"SpecialAccounts: {e}")

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
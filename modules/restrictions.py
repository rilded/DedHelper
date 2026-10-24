"""
Снятие ограничений Windows (офлайн-aware).

Изменения 7.2:
  * все ключи — через OfflineSession.open_hklm (WinPE -> реальный хайв)
  * HKCU-ограничения (DisallowRun, политики) — по всем загруженным пользователям
  * hosts — <drive>:\\Windows\\System32\\drivers\\etc\\hosts
"""
import winreg
import os
import subprocess
import shutil
import logging

try:
    from .offline import OfflineSession
except (ImportError, ValueError):
    from offline import OfflineSession

logger = logging.getLogger(__name__)


class RestrictionsManager:

    SCANCODE_SUBKEY = r'SYSTEM\CurrentControlSet\Control\Keyboard Layout'
    IFEO_SUBKEY = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    IFEO_WOW_SUBKEY = r'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    DISALLOWRUN_SUBKEY = r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    DISALLOWRUN_HKLM = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'

    def _hosts_path(self) -> str:
        return OfflineSession.windows('System32', 'drivers', 'etc', 'hosts')

    # ===================== SCANCODEMAP =====================
    def get_scancode_map(self):
        try:
            key = OfflineSession.open_hklm(self.SCANCODE_SUBKEY)
        except OSError:
            return None
        try:
            try:
                value, _ = winreg.QueryValueEx(key, 'Scancode Map')
                return value
            except OSError:
                return None
        finally:
            winreg.CloseKey(key)

    def remove_scancode_map(self) -> bool:
        try:
            key = OfflineSession.open_hklm(self.SCANCODE_SUBKEY,
                                            winreg.KEY_SET_VALUE | winreg.KEY_READ)
        except OSError as e:
            logger.error(f"remove_scancode_map open: {e}")
            return False
        try:
            try:
                winreg.DeleteValue(key, 'Scancode Map')
                return True
            except OSError as e:
                logger.error(f"remove_scancode_map delete: {e}")
                return False
        finally:
            winreg.CloseKey(key)

    # ===================== DEBUGGERS (IFEO) =====================
    def get_debuggers_list(self) -> list:
        result = []
        for subkey in (self.IFEO_SUBKEY, self.IFEO_WOW_SUBKEY):
            try:
                key = OfflineSession.open_hklm(subkey)
            except OSError:
                continue
            try:
                names = []
                i = 0
                while True:
                    try:
                        names.append(winreg.EnumKey(key, i))
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(key)
            for name in names:
                try:
                    sub = OfflineSession.open_hklm(subkey + '\\' + name)
                except OSError:
                    continue
                try:
                    try:
                        dbg, _ = winreg.QueryValueEx(sub, 'Debugger')
                        result.append({'application': name, 'debugger': str(dbg),
                                       'subkey': subkey})
                    except OSError:
                        pass
                finally:
                    winreg.CloseKey(sub)
        return result

    def remove_debugger(self, application: str) -> bool:
        ok = False
        for subkey in (self.IFEO_SUBKEY, self.IFEO_WOW_SUBKEY):
            try:
                key = OfflineSession.open_hklm(subkey + '\\' + application,
                                                winreg.KEY_SET_VALUE | winreg.KEY_READ)
            except OSError:
                continue
            try:
                try:
                    winreg.DeleteValue(key, 'Debugger')
                    ok = True
                except OSError:
                    pass
            finally:
                winreg.CloseKey(key)
        return ok

    def remove_all_debuggers(self) -> int:
        return sum(1 for d in self.get_debuggers_list()
                   if self.remove_debugger(d['application']))

    # ===================== DISALLOWRUN =====================
    def _iter_hkcu_roots(self):
        for label, hive, prefix in OfflineSession.hkcu_roots():
            yield label, hive, prefix

    def get_disallow_run(self) -> list:
        result = []
        # HKCU / всех пользователей
        for _label, hive, prefix in self._iter_hkcu_roots():
            full = (f"{prefix}\\{self.DISALLOWRUN_SUBKEY}"
                    if prefix else self.DISALLOWRUN_SUBKEY)
            for prog in self._read_disallow_values(hive, full):
                result.append(prog)
        # HKLM
        try:
            values = self._read_disallow_values(winreg.HKEY_LOCAL_MACHINE,
                                                self.DISALLOWRUN_HKLM,
                                                expand=False)
            result.extend(values)
        except OSError:
            pass
        return result

    def _read_disallow_values(self, hive, subpath, expand=True) -> list:
        out = []
        try:
            key = winreg.OpenKey(hive, subpath, 0, winreg.KEY_READ)
        except OSError:
            return out
        try:
            try:
                flag, _ = winreg.QueryValueEx(key, 'DisallowRun')
                if flag != 1:
                    return out
            except OSError:
                return out
            i = 0
            while True:
                try:
                    _vname, vdata, _vtype = winreg.EnumValue(key, i)
                    i += 1
                    out.append(str(vdata))
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)
        return out

    def remove_disallow_run(self) -> bool:
        ok = False
        # HKCU всех пользователей
        for _label, hive, prefix in self._iter_hkcu_roots():
            full = (f"{prefix}\\{self.DISALLOWRUN_SUBKEY}"
                    if prefix else self.DISALLOWRUN_SUBKEY)
            try:
                self._delete_disallow(hive, full)
                ok = True
            except OSError:
                pass
        # HKLM
        try:
            self._delete_disallow(winreg.HKEY_LOCAL_MACHINE, self.DISALLOWRUN_HKLM)
            ok = True
        except OSError:
            pass
        return ok

    def _delete_disallow(self, hive, subpath):
        key = winreg.OpenKey(hive, subpath, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ)
        try:
            try:
                winreg.DeleteValue(key, 'DisallowRun')
            except OSError:
                pass
            for i in range(100):
                try:
                    winreg.DeleteValue(key, str(i))
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)

    # ===================== HOSTS =====================
    def get_hosts_content(self) -> str:
        path = self._hosts_path()
        for enc in ('utf-8', 'cp1251', 'cp866'):
            try:
                with open(path, 'r', encoding=enc) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
            except OSError:
                return ""
        return ""

    def backup_hosts(self) -> bool:
        path = self._hosts_path()
        try:
            shutil.copy2(path, path + '.backup')
            return True
        except OSError:
            return False

    def restore_hosts_default(self) -> bool:
        path = self._hosts_path()
        default = (
            "# Copyright (c) 1993-2009 Microsoft Corp.\n"
            "#\n"
            "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n"
            "#\n"
            "# localhost name resolution is handled within DNS itself.\n"
            "#\t127.0.0.1       localhost\n"
            "#\t::1             localhost\n"
        )
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(default)
            return True
        except OSError as e:
            logger.error(f"restore_hosts_default: {e}")
            return False

    def clean_hosts(self) -> bool:
        try:
            content = self.get_hosts_content()
            kept = []
            for line in content.split('\n'):
                s = line.strip()
                if not s or s.startswith('#') or \
                        (('localhost' in s) and ('127.0.0.1' in s or '::1' in s)):
                    kept.append(line)
            with open(self._hosts_path(), 'w', encoding='utf-8') as f:
                f.write('\n'.join(kept))
            return True
        except OSError as e:
            logger.error(f"clean_hosts: {e}")
            return False

    # ===================== ОБЩИЕ ОГРАНИЧЕНИЯ =====================
    def get_all_restrictions(self) -> dict:
        return {
            'scancode_map': self.get_scancode_map() is not None,
            'debuggers': self.get_debuggers_list(),
            'disallow_run': self.get_disallow_run(),
            'hosts_content': self.get_hosts_content(),
        }

    def list_group_policies(self) -> list:
        result = []
        # HKLM
        try:
            self._collect_key_values(
                winreg.HKEY_LOCAL_MACHINE, 'HKLM',
                r'SOFTWARE\Policies\Microsoft\Windows', result)
        except OSError:
            pass
        # HKCU всех пользователей
        for label, hive, prefix in self._iter_hkcu_roots():
            sub = (f"{prefix}\\Software\\Policies\\Microsoft\\Windows"
                   if prefix else r'Software\Policies\Microsoft\Windows')
            try:
                self._collect_key_values(hive, label, sub, result)
            except OSError:
                pass
        return result

    def _collect_key_values(self, hive, hive_name, key_path, out, depth=0):
        if depth > 6:
            return
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        except OSError:
            return
        try:
            i = 0
            while True:
                try:
                    vname, vdata, _ = winreg.EnumValue(key, i)
                    out.append({'hive': hive_name, 'path': key_path,
                                'name': vname or '(default)', 'value': vdata})
                    i += 1
                except OSError:
                    break
            i = 0
            subs = []
            while True:
                try:
                    subs.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)
        for sub in subs:
            self._collect_key_values(hive, hive_name, key_path + '\\' + sub,
                                     out, depth + 1)

    def scan_restrictions(self) -> list:
        items = []
        if self.get_scancode_map() is not None:
            items.append({
                'category': 'ScancodeMap', 'name': 'Переназначение клавиш',
                'detail': 'SYSTEM\\...\\Keyboard Layout\\Scancode Map',
                'key': 'scancode_map',
            })
        for d in self.get_debuggers_list():
            items.append({
                'category': 'IFEO Debugger', 'name': d['application'],
                'detail': d['debugger'],
                'key': 'debugger:' + d['application'],
            })
        for prog in self.get_disallow_run():
            items.append({
                'category': 'DisallowRun', 'name': prog,
                'detail': 'Запуск заблокирован через политику Explorer',
                'key': 'disallow_run',
            })
        for gp in self.list_group_policies():
            items.append({
                'category': 'Group Policy',
                'name': f"{gp['hive']}\\{gp['path']}\\{gp['name']}",
                'detail': str(gp['value']),
                'key': 'group_policy',
            })
        items.sort(key=lambda it: (it['category'], it['name']))
        return items

    def remove_restriction_item(self, item: dict) -> bool:
        key = item.get('key', '')
        if key == 'scancode_map':
            return self.remove_scancode_map()
        if key.startswith('debugger:'):
            return self.remove_debugger(key.split(':', 1)[1])
        if key == 'disallow_run':
            return self.remove_disallow_run()
        if key == 'group_policy':
            self.remove_group_policies()
            return True
        return False

    def remove_group_policies(self) -> int:
        count = 0
        # HKLM
        try:
            self._delete_key_tree(winreg.HKEY_LOCAL_MACHINE,
                                  r'SOFTWARE\Policies\Microsoft\Windows')
            count += 1
        except Exception:
            pass
        # HKCU всех пользователей
        for _label, hive, prefix in self._iter_hkcu_roots():
            sub = (f"{prefix}\\Software\\Policies\\Microsoft\\Windows"
                   if prefix else r'Software\Policies\Microsoft\Windows')
            try:
                self._delete_key_tree(hive, sub)
                count += 1
            except Exception:
                pass
        return count

    def _delete_key_tree(self, hive, key_path):
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_ALL_ACCESS)
        except OSError:
            return
        try:
            subs = []
            i = 0
            while True:
                try:
                    subs.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)
        for sub in subs:
            self._delete_key_tree(hive, key_path + '\\' + sub)
        # удалить все значения
        try:
            key = winreg.OpenKey(hive, key_path, 0,
                                 winreg.KEY_ALL_ACCESS)
            try:
                vals = []
                i = 0
                while True:
                    try:
                        vname, _, _ = winreg.EnumValue(key, i)
                        vals.append(vname)
                        i += 1
                    except OSError:
                        break
                for v in vals:
                    try:
                        winreg.DeleteValue(key, v)
                    except OSError:
                        pass
            finally:
                winreg.CloseKey(key)
        except OSError:
            pass

    def remove_all_restrictions(self) -> dict:
        return {
            'scancode_map': self.remove_scancode_map(),
            'debuggers': self.remove_all_debuggers(),
            'disallow_run': self.remove_disallow_run(),
            'group_policy': self.remove_group_policies(),
        }


def get_restrictions():
    return RestrictionsManager().get_all_restrictions()


def remove_all_restrictions():
    return RestrictionsManager().remove_all_restrictions()
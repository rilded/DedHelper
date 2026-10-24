"""
Редактор реестра (офлайн-aware).

Изменения 7.2:
  * В WinPE parse_key_path разворачивает:
      HKLM\\SOFTWARE\\... -> HKLM\\OFFLINE_SOFTWARE\\...
      HKLM\\SYSTEM\\CurrentControlSet\\... -> HKLM\\OFFLINE_SYSTEM\\ControlSet00N\\...
      HKLM\\SYSTEM\\... -> HKLM\\OFFLINE_SYSTEM\\...
      HKLM\\SAM / SECURITY / DEFAULT — аналогично
      HKCU\\... -> HKLM\\OFFLINE_NTUSER_<первый загруженный>\\...
  * Список OFFLINE_* виден прямо в дереве HKLM
"""
import winreg
import subprocess
import os

try:
    from .offline import OfflineSession
except (ImportError, ValueError):
    from offline import OfflineSession


class RegistryEditor:

    ROOT_KEYS = {
        'HKCR': winreg.HKEY_CLASSES_ROOT,
        'HKCU': winreg.HKEY_CURRENT_USER,
        'HKLM': winreg.HKEY_LOCAL_MACHINE,
        'HKU': winreg.HKEY_USERS,
        'HKCC': winreg.HKEY_CURRENT_CONFIG,
    }

    def parse_key_path(self, full_path: str) -> tuple:
        parts = full_path.split('\\', 1)
        root_name = parts[0].upper()
        sub_path = parts[1] if len(parts) > 1 else ''

        # ---- офлайн-роутинг ----
        if OfflineSession.active:
            if root_name in ('HKLM', 'HKEY_LOCAL_MACHINE'):
                expanded = OfflineSession.expand_hklm_path(sub_path) \
                    if sub_path else ''
                return (winreg.HKEY_LOCAL_MACHINE, expanded)
            if root_name in ('HKCU', 'HKEY_CURRENT_USER'):
                user = OfflineSession.first_loaded_user()
                if user:
                    prefix = f"OFFLINE_NTUSER_{user}"
                    full = f"{prefix}\\{sub_path}" if sub_path else prefix
                    return (winreg.HKEY_LOCAL_MACHINE, full)
            if root_name in ('HKCR', 'HKEY_CLASSES_ROOT'):
                base = f"{OfflineSession.hives.get('SOFTWARE', 'SOFTWARE')}\\Classes"
                full = f"{base}\\{sub_path}" if sub_path else base
                return (winreg.HKEY_LOCAL_MACHINE, full)

        root_key = self.ROOT_KEYS.get(root_name)
        if not root_key:
            for name, key in self.ROOT_KEYS.items():
                if name.startswith(root_name) or root_name.startswith(name):
                    root_key = key
                    break
        return root_key, sub_path

    def _open(self, full_path, access):
        root_key, sub_path = self.parse_key_path(full_path)
        if root_key is None:
            raise FileNotFoundError(f"Bad root: {full_path}")
        return winreg.OpenKey(root_key, sub_path, 0, access)

    def _create(self, full_path, access):
        root_key, sub_path = self.parse_key_path(full_path)
        if root_key is None:
            raise FileNotFoundError(f"Bad root: {full_path}")
        return winreg.CreateKeyEx(root_key, sub_path, 0, access)

    def read_key(self, full_path, value_name=None):
        result = {'success': False, 'value': None, 'type': None, 'error': None}
        try:
            key = self._open(full_path, winreg.KEY_READ)
            try:
                if value_name:
                    value, vtype = winreg.QueryValueEx(key, value_name)
                    result['value'] = value
                    result['type'] = self._get_type_name(vtype)
                else:
                    values = {}
                    i = 0
                    while True:
                        try:
                            vname, vdata, vtype = winreg.EnumValue(key, i)
                            values[vname] = {'value': vdata,
                                             'type': self._get_type_name(vtype)}
                            i += 1
                        except OSError:
                            break
                    result['value'] = values
                result['success'] = True
            finally:
                winreg.CloseKey(key)
        except FileNotFoundError:
            result['error'] = 'Ключ не найден'
        except PermissionError:
            result['error'] = 'Нет доступа'
        except Exception as e:
            result['error'] = str(e)
        return result

    def write_key(self, full_path, value_name, value, value_type=winreg.REG_SZ):
        try:
            key = self._create(full_path, winreg.KEY_SET_VALUE)
            try:
                winreg.SetValueEx(key, value_name, 0, value_type, value)
            finally:
                winreg.CloseKey(key)
            return True
        except Exception:
            return False

    def delete_key(self, full_path, value_name=None):
        try:
            root_key, sub_path = self.parse_key_path(full_path)
            if root_key is None:
                return False
            if value_name is not None:
                key = winreg.OpenKey(root_key, sub_path, 0, winreg.KEY_SET_VALUE)
                try:
                    winreg.DeleteValue(key, value_name)
                finally:
                    winreg.CloseKey(key)
            else:
                if '\\' in sub_path:
                    parent_path, key_name = sub_path.rsplit('\\', 1)
                    parent = winreg.OpenKey(root_key, parent_path, 0,
                                             winreg.KEY_SET_VALUE)
                    try:
                        winreg.DeleteKey(parent, key_name)
                    finally:
                        winreg.CloseKey(parent)
                else:
                    winreg.DeleteKey(root_key, sub_path)
            return True
        except Exception:
            return False

    def root_names(self):
        return list(self.ROOT_KEYS.keys())

    def key_exists(self, full_path):
        try:
            key = self._open(full_path, winreg.KEY_READ)
            winreg.CloseKey(key)
            return True
        except OSError:
            return False

    def list_subkeys(self, full_path):
        try:
            key = self._open(full_path, winreg.KEY_READ)
        except OSError:
            return []
        try:
            names = []
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
            names.sort(key=str.lower)
            return names
        finally:
            winreg.CloseKey(key)

    def has_subkeys(self, full_path):
        try:
            key = self._open(full_path, winreg.KEY_READ)
        except OSError:
            return False
        try:
            winreg.EnumKey(key, 0)
            return True
        except OSError:
            return False
        finally:
            winreg.CloseKey(key)

    def list_values(self, full_path):
        try:
            key = self._open(full_path, winreg.KEY_READ)
        except OSError:
            return []
        try:
            out = []
            i = 0
            while True:
                try:
                    vname, vdata, vtype = winreg.EnumValue(key, i)
                    out.append({'name': vname, 'value': vdata,
                                'type': self._get_type_name(vtype),
                                'raw_type': vtype})
                    i += 1
                except OSError:
                    break
            out.sort(key=lambda v: (v['name'] != '', v['name'].lower()))
            return out
        finally:
            winreg.CloseKey(key)

    def rename_value(self, full_path, old_name, new_name):
        try:
            key = self._open(full_path, winreg.KEY_ALL_ACCESS)
            try:
                value, vtype = winreg.QueryValueEx(key, old_name)
                winreg.SetValueEx(key, new_name, 0, vtype, value)
                winreg.DeleteValue(key, old_name)
            finally:
                winreg.CloseKey(key)
            return True
        except Exception:
            return False

    def rename_key(self, full_path, new_name):
        try:
            parent_path, _old_name = full_path.rsplit('\\', 1)
            new_path = parent_path + '\\' + new_name
            if not self._copy_key_recursive(full_path, new_path):
                return False
            return self.delete_key_recursive(full_path)
        except Exception:
            return False

    def delete_key_recursive(self, full_path):
        try:
            for sub in self.list_subkeys(full_path):
                if not self.delete_key_recursive(full_path + '\\' + sub):
                    return False
            return self.delete_key(full_path)
        except Exception:
            return False

    def _copy_key_recursive(self, src_path, dst_path):
        if not self.create_key(dst_path):
            return False
        for v in self.list_values(src_path):
            if not self.write_key(dst_path, v['name'], v['value'], v['raw_type']):
                return False
        for sub in self.list_subkeys(src_path):
            if not self._copy_key_recursive(src_path + '\\' + sub,
                                            dst_path + '\\' + sub):
                return False
        return True

    def create_key(self, full_path):
        try:
            key = self._create(full_path, winreg.KEY_ALL_ACCESS)
            winreg.CloseKey(key)
            return True
        except Exception:
            return False

    def export_key(self, full_path, output_file):
        try:
            r = subprocess.run(
                f'reg export "{full_path}" "{output_file}" /y',
                shell=True, capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    def import_key(self, reg_file):
        try:
            r = subprocess.run(f'reg import "{reg_file}"',
                               shell=True, capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    def search_keys(self, root, search_term, search_type='all'):
        try:
            r = subprocess.run(f'reg query "{root}" /f "{search_term}" /s',
                               shell=True, capture_output=True, text=True,
                               encoding='cp866')
            if r.returncode == 0:
                return [l.strip() for l in r.stdout.split('\n') if l.strip()]
        except Exception:
            pass
        return []

    def get_key_permissions(self, full_path):
        result = {'read': False, 'write': False, 'delete': False,
                  'full_control': False}
        for flag, key in (('read', winreg.KEY_READ),
                          ('write', winreg.KEY_WRITE),
                          ('full_control', winreg.KEY_ALL_ACCESS)):
            try:
                k = self._open(full_path, key)
                winreg.CloseKey(k)
                result[flag] = True
            except Exception:
                pass
        return result

    def take_key_ownership(self, full_path):
        try:
            reg_path = full_path.replace('\\', '\\\\')
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                              delete=False) as f:
                f.write(f'{reg_path} FULL_ACCESS\n')
                temp_file = f.name
            r = subprocess.run(f'regini "{temp_file}"', shell=True,
                               capture_output=True, text=True)
            try:
                os.unlink(temp_file)
            except OSError:
                pass
            return r.returncode == 0
        except Exception:
            return False

    def backup_hive(self, hive, output_file):
        try:
            r = subprocess.run(f'reg save HKLM\\{hive} "{output_file}"',
                               shell=True, capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    def restore_hive(self, hive, backup_file):
        try:
            r = subprocess.run(f'reg restore HKLM\\{hive} "{backup_file}"',
                               shell=True, capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _get_type_name(value_type):
        return {
            winreg.REG_SZ: 'REG_SZ',
            winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
            winreg.REG_BINARY: 'REG_BINARY',
            winreg.REG_DWORD: 'REG_DWORD',
            winreg.REG_DWORD_LITTLE_ENDIAN: 'REG_DWORD_LE',
            winreg.REG_DWORD_BIG_ENDIAN: 'REG_DWORD_BE',
            winreg.REG_LINK: 'REG_LINK',
            winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
            winreg.REG_RESOURCE_LIST: 'REG_RESOURCE_LIST',
            winreg.REG_FULL_RESOURCE_DESCRIPTOR: 'REG_FULL_RESOURCE_DESCRIPTOR',
            winreg.REG_RESOURCE_REQUIREMENTS_LIST: 'REG_RESOURCE_REQUIREMENTS_LIST',
            winreg.REG_QWORD: 'REG_QWORD',
        }.get(value_type, f'UNKNOWN({value_type})')

    def open_regedit(self):
        try:
            subprocess.Popen('regedit.exe')
            return True
        except Exception:
            return False


def read_registry(full_path, value_name=None):
    return RegistryEditor().read_key(full_path, value_name)


def write_registry(full_path, value_name, value, value_type=winreg.REG_SZ):
    return RegistryEditor().write_key(full_path, value_name, value, value_type)


def delete_registry(full_path, value_name=None):
    return RegistryEditor().delete_key(full_path, value_name)


def open_regedit():
    return RegistryEditor().open_regedit()
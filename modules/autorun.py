"""
Управление автозагрузкой Windows (офлайн-aware).

Изменения 7.2:
  * Реестр читается через OfflineSession (WinPE -> реальный хайв)
  * Планировщик в офлайне — прямая работа с <drive>:\\Windows\\System32\\Tasks\\*.xml
  * Службы в офлайне — чтение OFFLINE_SYSTEM\\ControlSet00N\\Services
  * Папки автозагрузки — по всем пользователям
"""
import winreg
import os
import subprocess
import csv
import io
import re
import logging

try:
    from .offline import OfflineSession
except (ImportError, ValueError):
    from offline import OfflineSession

logger = logging.getLogger(__name__)


class AutorunManager:
    """Управление всеми типами автозагрузки."""

    BOOT_EXECUTE_DEFAULT = ['autocheck autochk *']
    IFEO_SUBKEY = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

    def __init__(self):
        self._autorun_location_map = {}

    # ===================== РЕЕСТР =====================
        # ===================== РЕЕСТР =====================
    def get_registry_autoruns(self) -> list:
        """
        Возвращает [{category, location, display_location, name, value}, ...].
        display_location — красивый путь для отображения в дереве.
        """
        self._autorun_location_map = {}
        rows = []

        # HKCU (в офлайне - все пользователи)
        specs_hkcu = [
            (r'Software\Microsoft\Windows\CurrentVersion\Run', 'Run/RunOnce', 'Run'),
            (r'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'Run/RunOnce', 'RunOnce'),
            (r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Winlogon', 'Winlogon'),
        ]
        for label, hive, prefix in OfflineSession.hkcu_roots():
            tag = label.replace(' ', '_').replace('(', '').replace(')', '')
            for subpath, category, short in specs_hkcu:
                full = f"{prefix}\\{subpath}" if prefix else subpath
                loc_key = f"{tag}_{short}"
                try:
                    values = self._enum_values(hive, full)
                except OSError:
                    continue
                if values:
                    self._autorun_location_map[loc_key] = (hive, full)
                    display_loc = f"{label}\\{subpath}" if OfflineSession.active else f"HKCU\\{subpath}"
                    for name, value in values:
                        rows.append({
                            'category': category, 'location': loc_key,
                            'display_location': display_loc,
                            'name': name, 'value': str(value),
                        })

        # HKLM (все системные ветки)
        specs_hklm = [
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'Run/RunOnce', 'HKLM_Run'),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'Run/RunOnce', 'HKLM_RunOnce'),
            (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Winlogon', 'HKLM_Winlogon'),
            (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'Windows', 'HKLM_Windows_64'),
            (r'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows', 'Windows', 'HKLM_Windows_32'),
            (r'SYSTEM\Setup', 'Setup', 'HKLM_Setup'),
            (r'SYSTEM\CurrentControlSet\Control\SafeBoot', 'SafeBoot', 'HKLM_SafeBoot'),
            (r'SYSTEM\CurrentControlSet\Control\Session Manager', 'Session Manager', 'HKLM_SessionManager'),
            (r'SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs', 'KnownDLLs', 'HKLM_KnownDLLs'),
        ]
        for subpath, category, loc_key in specs_hklm:
            try:
                full = OfflineSession.expand_hklm_path(subpath) if OfflineSession.active else subpath
                values = self._enum_values(winreg.HKEY_LOCAL_MACHINE, full)
            except OSError:
                continue
            if values:
                self._autorun_location_map[loc_key] = (winreg.HKEY_LOCAL_MACHINE, full)
                display_loc = f"HKLM\\{subpath}"
                for name, value in values:
                    rows.append({
                        'category': category, 'location': loc_key,
                        'display_location': display_loc,
                        'name': name, 'value': str(value),
                    })
        return rows

    @staticmethod
    def _enum_values(hive, subpath) -> list:
        try:
            key = winreg.OpenKey(hive, subpath, 0, winreg.KEY_READ)
        except OSError:
            return []
        try:
            out = []
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    # Если значение является списком строк (REG_MULTI_SZ), склеиваем их
                    if isinstance(value, list):
                        value = ' | '.join(str(v) for v in value)
                    out.append((name, str(value)))
                    i += 1
                except OSError:
                    break
            return out
        finally:
            winreg.CloseKey(key)

    def remove_registry_autorun(self, name: str, location: str) -> bool:
        hive_subpath = self._autorun_location_map.get(location)
        if not hive_subpath:
            return False
        hive, subpath = hive_subpath
        try:
            key = winreg.OpenKey(hive, subpath, 0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(key, name)
            finally:
                winreg.CloseKey(key)
            return True
        except OSError as e:
            logger.error(f"remove_registry_autorun({name}, {location}): {e}")
            return False

    def add_registry_autorun(self, name: str, path: str, location: str = 'HKCU_Run') -> bool:
        try:
            if location.startswith('HKCU'):
                key = OfflineSession.create_hkcu(r'Software\Microsoft\Windows\CurrentVersion\Run')
            elif location.startswith('HKLM'):
                key = OfflineSession.create_hklm(r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run')
            else:
                return False
            try:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, f'"{path}"')
            finally:
                winreg.CloseKey(key)
            return True
        except Exception as e:
            logger.error(f"add_registry_autorun: {e}")
            return False

    def set_registry_autorun(self, name: str, new_value: str, location: str) -> bool:
        """
        Изменить значение существующего элемента автозагрузки.
        Тип (REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ) сохраняется от старого.
        """
        hive_subpath = self._autorun_location_map.get(location)
        if not hive_subpath:
            logger.error(f"set_registry_autorun: location '{location}' неизвестен")
            return False
        hive, subpath = hive_subpath
        try:
            key = winreg.OpenKey(hive, subpath, 0,
                                 winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE)
        except OSError as e:
            logger.error(f"set_registry_autorun open({location}): {e}")
            return False
        try:
            try:
                _old, vtype = winreg.QueryValueEx(key, name)
            except FileNotFoundError:
                vtype = winreg.REG_SZ
            except OSError as e:
                logger.error(f"set_registry_autorun read({name}): {e}")
                return False

            if vtype == winreg.REG_MULTI_SZ:
                value_data = [v for v in new_value.split('\n') if v != '']
            else:
                value_data = str(new_value)

            try:
                winreg.SetValueEx(key, name, 0, vtype, value_data)
                logger.info(f"Автозагрузка изменена: {name} @ {location} -> {new_value!r}")
                return True
            except OSError as e:
                logger.error(f"set_registry_autorun write({name}): {e}")
                return False
        finally:
            winreg.CloseKey(key)

    # ===================== ПАПКА АВТОЗАГРУЗКИ =====================
    def get_startup_folder_items(self) -> list:
        items = []
        for label, folder in OfflineSession.startup_dirs():
            if not os.path.isdir(folder):
                continue
            try:
                for item in os.listdir(folder):
                    full = os.path.join(folder, item)
                    if not os.path.isfile(full):
                        continue
                    items.append({
                        'category': 'Папка автозагрузки',
                        'location': label,
                        'name': item,
                        'value': full,
                    })
            except OSError as e:
                logger.debug(f"startup {folder}: {e}")
        return items

    def remove_from_startup(self, filename: str) -> bool:
        removed = False
        for _label, folder in OfflineSession.startup_dirs():
            path = os.path.join(folder, filename)
            if os.path.isfile(path):
                try:
                    os.remove(path)
                    removed = True
                except OSError as e:
                    logger.error(f"remove_from_startup({path}): {e}")
        return removed

    # ===================== ПЛАНИРОВЩИК =====================
    def get_scheduled_tasks(self) -> list:
        if OfflineSession.active:
            return self._scheduled_offline()
        return self._scheduled_online()

    def _scheduled_online(self) -> list:
        tasks = []
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'CSV', '/nh'],
                capture_output=True, text=True, encoding='cp866', errors='ignore',
            )
            reader = csv.reader(io.StringIO(result.stdout))
            for row in reader:
                if len(row) >= 2 and row[0].strip():
                    tasks.append({'name': row[0].strip()})
        except Exception as e:
            logger.error(f"get_scheduled_tasks (online): {e}")
        return tasks

    def _scheduled_offline(self) -> list:
        tasks_dir = OfflineSession.windows('System32', 'Tasks')
        tasks = []
        if not os.path.isdir(tasks_dir):
            return tasks
        for root, _dirs, files in os.walk(tasks_dir):
            for f in files:
                if f == 'SA.DAT':
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, tasks_dir)
                tasks.append({'name': rel, 'path': full})
        return tasks

    def delete_scheduled_task(self, name: str) -> bool:
        if OfflineSession.active:
            full = os.path.join(OfflineSession.windows('System32', 'Tasks'), name)
            try:
                if os.path.isfile(full):
                    os.remove(full)
                    return True
            except OSError as e:
                logger.error(f"delete_scheduled_task (offline): {e}")
            return False
        try:
            r = subprocess.run(f'schtasks /delete /tn "{name}" /f',
                               shell=True, capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    def enable_scheduled_task(self, name: str) -> bool:
        if OfflineSession.active:
            return self._offline_set_enabled(name, True)
        try:
            r = subprocess.run(f'schtasks /change /tn "{name}" /enable',
                               shell=True, capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    def disable_scheduled_task(self, name: str) -> bool:
        if OfflineSession.active:
            return self._offline_set_enabled(name, False)
        try:
            r = subprocess.run(f'schtasks /change /tn "{name}" /disable',
                               shell=True, capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    def _offline_set_enabled(self, name: str, enabled: bool) -> bool:
        full = os.path.join(OfflineSession.windows('System32', 'Tasks'), name)
        if not os.path.isfile(full):
            return False
        content = self._read_task_xml(full)
        if content is None:
            return False
        val = 'true' if enabled else 'false'
        if re.search(r'<Enabled>\s*(true|false)\s*</Enabled>', content):
            content = re.sub(r'<Enabled>\s*(true|false)\s*</Enabled>',
                             f'<Enabled>{val}</Enabled>', content)
        else:
            content = content.replace('</Settings>',
                                      f'<Enabled>{val}</Enabled></Settings>')
        try:
            with open(full, 'w', encoding='utf-16') as f:
                f.write(content)
            return True
        except OSError as e:
            logger.error(f"_offline_set_enabled({name}): {e}")
            return False

    @staticmethod
    def _read_task_xml(path):
        for enc in ('utf-16', 'utf-8', 'cp1251'):
            try:
                with open(path, 'r', encoding=enc) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
            except OSError:
                return None
        return None

    # ===================== СЛУЖБЫ / ДРАЙВЕРЫ =====================
    def get_services(self) -> list:
        return (self._services_offline(is_driver=False) if OfflineSession.active
                else self._services_online('service'))

    def get_drivers(self) -> list:
        return (self._services_offline(is_driver=True) if OfflineSession.active
                else self._services_online('driver'))

    def _services_offline(self, is_driver: bool) -> list:
        items = []
        try:
            key = OfflineSession.open_hklm(r'SYSTEM\CurrentControlSet\Services')
        except OSError as e:
            logger.error(f"_services_offline open: {e}")
            return items
        try:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(key, i)
                    i += 1
                except OSError:
                    break
                try:
                    sub = winreg.OpenKey(key, name, 0, winreg.KEY_READ)
                except OSError:
                    continue
                try:
                    stype = 0
                    try:
                        stype, _ = winreg.QueryValueEx(sub, 'Type')
                    except OSError:
                        pass
                    disp = name
                    try:
                        disp, _ = winreg.QueryValueEx(sub, 'DisplayName')
                    except OSError:
                        pass
                    start = 3
                    try:
                        start, _ = winreg.QueryValueEx(sub, 'Start')
                    except OSError:
                        pass
                finally:
                    winreg.CloseKey(sub)

                svc_type = bool(stype & 0x10) or bool(stype & 0x20)
                drv_type = (not svc_type) and stype != 0
                if is_driver and not drv_type:
                    continue
                if not is_driver and not svc_type:
                    continue

                state = {0: 'boot', 1: 'system', 2: 'auto',
                         3: 'manual', 4: 'disabled'}.get(start, '?')
                items.append({
                    'name': name,
                    'display_name': str(disp),
                    'state': f"Start={state}",
                })
        finally:
            winreg.CloseKey(key)
        return items

    def _services_online(self, type_filter: str) -> list:
        items = []
        try:
            result = subprocess.run(
                ['sc', 'query', 'type=', type_filter, 'state=', 'all'],
                capture_output=True, text=True, encoding='cp866', errors='ignore',
            )
            current = {}
            for line in result.stdout.split('\n'):
                if line.startswith('SERVICE_NAME:'):
                    if current:
                        items.append(current)
                    current = {'name': line.split(':', 1)[1].strip()}
                elif 'DISPLAY_NAME:' in line:
                    current['display_name'] = line.split(':', 1)[1].strip()
                elif 'STATE' in line:
                    current['state'] = 'running' if 'RUNNING' in line else 'stopped'
            if current:
                items.append(current)
        except Exception as e:
            logger.error(f"sc query: {e}")
        return items

    def _offline_set_service_start(self, name: str, start: int) -> bool:
        try:
            key = OfflineSession.open_hklm(
                rf'SYSTEM\CurrentControlSet\Services\{name}',
                winreg.KEY_SET_VALUE | winreg.KEY_READ)
            try:
                winreg.SetValueEx(key, 'Start', 0, winreg.REG_DWORD, start)
            finally:
                winreg.CloseKey(key)
            return True
        except OSError as e:
            logger.error(f"_offline_set_service_start({name}): {e}")
            return False

    def start_service(self, name: str) -> bool:
        if OfflineSession.active:
            logger.warning(f"start_service({name}) недоступен в офлайне")
            return False
        try:
            r = subprocess.run(f'sc start "{name}"', shell=True,
                               capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    def stop_service(self, name: str) -> bool:
        if OfflineSession.active:
            logger.warning(f"stop_service({name}) недоступен в офлайне")
            return False
        try:
            r = subprocess.run(f'sc stop "{name}"', shell=True,
                               capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    def disable_service(self, name: str) -> bool:
        if OfflineSession.active:
            return self._offline_set_service_start(name, 4)
        try:
            r = subprocess.run(f'sc config "{name}" start= disabled', shell=True,
                               capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    def enable_service(self, name: str) -> bool:
        if OfflineSession.active:
            return self._offline_set_service_start(name, 2)
        try:
            r = subprocess.run(f'sc config "{name}" start= auto', shell=True,
                               capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    def delete_service(self, name: str) -> bool:
        if OfflineSession.active:
            try:
                sub = OfflineSession.expand_hklm_path(
                    rf'SYSTEM\CurrentControlSet\Services\{name}')
                self._delete_reg_key_recursive(winreg.HKEY_LOCAL_MACHINE, sub)
                return True
            except Exception:
                return False
        try:
            r = subprocess.run(f'sc delete "{name}"', shell=True,
                               capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _delete_reg_key_recursive(hive, path):
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
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
            AutorunManager._delete_reg_key_recursive(hive, path + '\\' + sub)
        if '\\' in path:
            parent_path, sub_name = path.rsplit('\\', 1)
            try:
                parent = winreg.OpenKey(hive, parent_path, 0, winreg.KEY_ALL_ACCESS)
                try:
                    winreg.DeleteKey(parent, sub_name)
                finally:
                    winreg.CloseKey(parent)
            except OSError:
                pass

    # ===================== BOOTEXECUTE =====================
    def get_boot_execute(self) -> dict:
        result = {'values': [], 'is_default': True}
        try:
            key = OfflineSession.open_hklm(
                r'SYSTEM\CurrentControlSet\Control\Session Manager')
        except OSError:
            return result
        try:
            try:
                values, _ = winreg.QueryValueEx(key, 'BootExecute')
                result['values'] = list(values) if values else []
            except OSError:
                pass
        finally:
            winreg.CloseKey(key)
        result['is_default'] = (result['values'] == self.BOOT_EXECUTE_DEFAULT)
        return result

    def set_boot_execute(self, values: list) -> bool:
        try:
            key = OfflineSession.open_hklm(
                r'SYSTEM\CurrentControlSet\Control\Session Manager',
                winreg.KEY_SET_VALUE | winreg.KEY_READ)
            try:
                winreg.SetValueEx(key, 'BootExecute', 0, winreg.REG_MULTI_SZ, values)
            finally:
                winreg.CloseKey(key)
            return True
        except OSError as e:
            logger.error(f"set_boot_execute: {e}")
            return False

    # ===================== IFEO =====================
    IFEO_SUBKEYS = (
        r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        r'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    )

    def get_ifeo_entries(self) -> list:
        """
        Возвращает ВСЕ подразделы IFEO (x64 + WOW64), включая те,
        у которых нет Debugger — с перечнем всех значений.
        """
        result = []
        for base in self.IFEO_SUBKEYS:
            try:
                key = OfflineSession.open_hklm(base)
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
                    sub = OfflineSession.open_hklm(base + '\\' + name)
                except OSError:
                    continue
                try:
                    debugger = None
                    try:
                        debugger, _ = winreg.QueryValueEx(sub, 'Debugger')
                    except OSError:
                        pass

                    if debugger is not None:
                        value = str(debugger)
                    else:
                        # собираем все значения подраздела, чтобы было видно, что там
                        bits = []
                        j = 0
                        while True:
                            try:
                                vn, vv, _ = winreg.EnumValue(sub, j)
                                j += 1
                            except OSError:
                                break
                            # MULTI_SZ приходит списком — схлопнем
                            if isinstance(vv, list):
                                vv = '|'.join(map(str, vv))
                            bits.append(f"{vn or '(default)'}={vv}")
                        value = '; '.join(bits) if bits else '(пусто)'

                    result.append({
                        'application': name,
                        'debugger': value,
                        'arch': '32' if 'WOW6432Node' in base else '64',
                    })
                finally:
                    winreg.CloseKey(sub)
        return result

    # старая сигнатура — оставляем как алиас, чтобы не ломать вызовы
    def get_ifeo_debuggers(self) -> list:
        return self.get_ifeo_entries()

    def remove_ifeo_debugger(self, application: str) -> bool:
        try:
            key = OfflineSession.open_hklm(
                self.IFEO_SUBKEY + '\\' + application,
                winreg.KEY_SET_VALUE | winreg.KEY_READ)
            try:
                winreg.DeleteValue(key, 'Debugger')
            finally:
                winreg.CloseKey(key)
            return True
        except OSError:
            return False

    # ===================== CLSID =====================
    def get_clsid_overrides(self) -> list:
        """
        Переопределения CLSID (HKCU-обёртка над HKLM-регистрацией) — есть
        смысл только в online-режиме: в офлайне для каждого юзера нужно
        отдельно грузить NTUSER+SYSTEM и сравнивать, слишком дорого.
        В офлайне возвращаем пустой список.
        """
        result = []
        try:
            hkcu_classes = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, r'Software\Classes\CLSID', 0, winreg.KEY_READ)
        except OSError:
            return result
        try:
            clsids = []
            i = 0
            while True:
                try:
                    clsids.append(winreg.EnumKey(hkcu_classes, i))
                    i += 1
                except OSError:
                    break
        finally:
            winreg.CloseKey(hkcu_classes)

        for clsid in clsids:
            for server in ('InprocServer32', 'LocalServer32'):
                hkcu_val = self._read_default(
                    winreg.HKEY_CURRENT_USER,
                    f'Software\\Classes\\CLSID\\{clsid}\\{server}')
                if hkcu_val is None:
                    continue
                hklm_val = self._read_default(
                    winreg.HKEY_LOCAL_MACHINE,
                    f'SOFTWARE\\Classes\\CLSID\\{clsid}\\{server}')
                if hklm_val is not None and hklm_val.lower() != hkcu_val.lower():
                    result.append({'clsid': clsid, 'server': server,
                                   'hkcu_value': hkcu_val, 'hklm_value': hklm_val})
        return result

    @staticmethod
    def _read_default(hive, path):
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        except OSError:
            return None
        try:
            val, _ = winreg.QueryValueEx(key, '')
            return str(val) if val else None
        except OSError:
            return None
        finally:
            winreg.CloseKey(key)

    def remove_clsid_override(self, clsid: str) -> bool:
        if OfflineSession.active:
            return False
        try:
            self._delete_reg_key_recursive(
                winreg.HKEY_CURRENT_USER, f'Software\\Classes\\CLSID\\{clsid}')
            return True
        except Exception:
            return False

    # ===================== СБОРНЫЙ СПИСОК / ОЧИСТКА =====================
    def get_sorted_autorun(self) -> list:
        rows = []
        for r in self.get_registry_autoruns():
            rows.append({
                'category': r['category'],
                'location': r['location'],
                'display_location': r['display_location'],
                'name': r['name'],
                'value': r['value'],
                'safe_to_bulk_clear': r['category'] == 'Run/RunOnce',
            })
        for item in self.get_startup_folder_items():
            rows.append({
                'category': 'Папка автозагрузки',
                'location': item['location'],
                'display_location': f"Startup: {item['location']}",
                'name': item['name'],
                'value': item['value'],
                'safe_to_bulk_clear': True,
            })
        # Блок BootExecute убран, так как он теперь в Session Manager
        for d in self.get_ifeo_entries():
            rows.append({
                'category': f"CmdLine (IFEO, {d.get('arch','?')}-bit)",
                'location': 'Image File Execution Options',
                'display_location': f"HKLM\\...\\Image File Execution Options ({d.get('arch','?')}-bit)",
                'name': d['application'],
                'value': d['debugger'],
                'safe_to_bulk_clear': False,
            })
        for c in self.get_clsid_overrides():
            rows.append({
                'category': 'CLSID', 'location': c['server'],
                'display_location': f"HKCU\\Software\\Classes\\CLSID\\{c['clsid']}\\{c['server']}",
                'name': c['clsid'], 'value': c['hkcu_value'],
                'safe_to_bulk_clear': False,
            })
        rows.sort(key=lambda r: (r.get('display_location', ''), r['name'].lower()))
        return rows

    def clear_safe_autorun(self) -> int:
        removed = 0
        for r in self.get_registry_autoruns():
            if r['category'] == 'Run/RunOnce':
                if self.remove_registry_autorun(r['name'], r['location']):
                    removed += 1
        for item in self.get_startup_folder_items():
            try:
                if os.path.isfile(item['value']):
                    os.remove(item['value'])
                    removed += 1
            except OSError:
                pass
        return removed


def get_all_autoruns():
    return AutorunManager().get_sorted_autorun()


def remove_autorun(location, name):
    return AutorunManager().remove_registry_autorun(name, location)

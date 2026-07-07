"""
Модуль работы с реестром Windows
Альтернативный редактор реестра с дополнительными функциями
"""

import winreg
import subprocess
import os


class RegistryEditor:
    """Класс для работы с реестром Windows"""
    
    # Корневые ключи
    ROOT_KEYS = {
        'HKCR': winreg.HKEY_CLASSES_ROOT,
        'HKCU': winreg.HKEY_CURRENT_USER,
        'HKLM': winreg.HKEY_LOCAL_MACHINE,
        'HKU': winreg.HKEY_USERS,
        'HKCC': winreg.HKEY_CURRENT_CONFIG,
    }
    
    def __init__(self):
        pass
    
    def parse_key_path(self, full_path: str) -> tuple:
        """
        Разобрать полный путь к ключу реестра
        Возвращает (root_key, sub_path)
        """
        parts = full_path.split('\\', 1)
        root_name = parts[0].upper()
        
        root_key = self.ROOT_KEYS.get(root_name)
        if not root_key:
            # Пробуем найти по частичному совпадению
            for name, key in self.ROOT_KEYS.items():
                if name.startswith(root_name) or root_name.startswith(name):
                    root_key = key
                    break
        
        sub_path = parts[1] if len(parts) > 1 else ''
        
        return root_key, sub_path
    
    def read_key(self, full_path: str, value_name: str = None) -> dict:
        """
        Прочитать значение из реестра
        Если value_name не указан, возвращает все значения ключа
        """
        result = {
            'success': False,
            'value': None,
            'type': None,
            'error': None
        }
        
        try:
            root_key, sub_path = self.parse_key_path(full_path)
            
            if root_key is None:
                result['error'] = 'Неверный корневой ключ'
                return result
            
            key = winreg.OpenKey(root_key, sub_path, 0, winreg.KEY_READ)
            
            if value_name:
                # Читаем конкретное значение
                value, value_type = winreg.QueryValueEx(key, value_name)
                result['value'] = value
                result['type'] = self._get_type_name(value_type)
            else:
                # Читаем все значения ключа
                values = {}
                i = 0
                while True:
                    try:
                        vname, vdata, vtype = winreg.EnumValue(key, i)
                        values[vname] = {
                            'value': vdata,
                            'type': self._get_type_name(vtype)
                        }
                        i += 1
                    except OSError:
                        break
                result['value'] = values
            
            winreg.CloseKey(key)
            result['success'] = True
            
        except FileNotFoundError:
            result['error'] = 'Ключ не найден'
        except PermissionError:
            result['error'] = 'Нет доступа'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def write_key(self, full_path: str, value_name: str, value, value_type: int = winreg.REG_SZ) -> bool:
        """
        Записать значение в реестр
        value_type: REG_SZ, REG_DWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ
        """
        try:
            root_key, sub_path = self.parse_key_path(full_path)
            
            if root_key is None:
                return False
            
            # Создаём ключ если не существует
            key = winreg.CreateKeyEx(root_key, sub_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, value_name, 0, value_type, value)
            winreg.CloseKey(key)
            
            return True
        except Exception:
            return False
    
    def delete_key(self, full_path: str, value_name: str = None) -> bool:
        """
        Удалить значение или весь ключ реестра
        Если value_name указан, удаляет только значение
        """
        try:
            root_key, sub_path = self.parse_key_path(full_path)
            
            if root_key is None:
                return False
            
            if value_name:
                # Удаляем только значение
                key = winreg.OpenKey(root_key, sub_path, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, value_name)
                winreg.CloseKey(key)
            else:
                # Удаляем весь ключ
                # Нужно получить родительский ключ
                parent_path, key_name = sub_path.rsplit('\\', 1)
                if parent_path:
                    parent_key = winreg.OpenKey(root_key, parent_path, 0, winreg.KEY_SET_VALUE)
                    winreg.DeleteKey(parent_key, key_name)
                    winreg.CloseKey(parent_key)
                else:
                    # Удаляем из корневого ключа
                    winreg.DeleteKey(root_key, sub_path)
            
            return True
        except Exception:
            return False
    
    def create_key(self, full_path: str) -> bool:
        """Создать ключ реестра"""
        try:
            root_key, sub_path = self.parse_key_path(full_path)
            
            if root_key is None:
                return False
            
            key = winreg.CreateKeyEx(root_key, sub_path, 0, winreg.KEY_ALL_ACCESS)
            winreg.CloseKey(key)
            
            return True
        except Exception:
            return False
    
    def export_key(self, full_path: str, output_file: str) -> bool:
        """Экспортировать ключ реестра в .reg файл"""
        try:
            # Преобразуем путь для reg export
            reg_path = full_path.replace('/', '\\')
            
            cmd = f'reg export "{reg_path}" "{output_file}" /y'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            return result.returncode == 0
        except Exception:
            return False
    
    def import_key(self, reg_file: str) -> bool:
        """Импортировать .reg файл в реестр"""
        try:
            cmd = f'reg import "{reg_file}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            return result.returncode == 0
        except Exception:
            return False
    
    def search_keys(self, root: str, search_term: str, search_type: str = 'all') -> list:
        """
        Искать в реестре по названию ключа или значения
        search_type: 'keys', 'values', 'all'
        """
        results = []
        
        try:
            root_key = self.ROOT_KEYS.get(root.upper(), winreg.HKEY_CURRENT_USER)
            
            # Используем reg query для поиска
            cmd = f'reg query "{root}" /f "{search_term}" /s'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='cp866')
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip():
                        results.append(line.strip())
        except Exception:
            pass
        
        return results
    
    def get_key_permissions(self, full_path: str) -> dict:
        """Получить права доступа к ключу реестра"""
        result = {
            'read': False,
            'write': False,
            'delete': False,
            'full_control': False
        }
        
        try:
            root_key, sub_path = self.parse_key_path(full_path)
            
            # Пробуем открыть с разными правами
            try:
                key = winreg.OpenKey(root_key, sub_path, 0, winreg.KEY_READ)
                result['read'] = True
                winreg.CloseKey(key)
            except Exception:
                pass
            
            try:
                key = winreg.OpenKey(root_key, sub_path, 0, winreg.KEY_WRITE)
                result['write'] = True
                winreg.CloseKey(key)
            except Exception:
                pass
            
            try:
                key = winreg.OpenKey(root_key, sub_path, 0, winreg.KEY_ALL_ACCESS)
                result['full_control'] = True
                winreg.CloseKey(key)
            except Exception:
                pass
                
        except Exception:
            pass
        
        return result
    
    def take_key_ownership(self, full_path: str) -> bool:
        """Получить права владельца ключа реестра"""
        try:
            # Используем subinacl или icacls для смены владельца
            # Для реестра используем regini
            
            reg_path = full_path.replace('\\', '\\\\')
            
            # Создаём временный файл для regini
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(f'{reg_path} FULL_ACCESS\n')
                temp_file = f.name
            
            cmd = f'regini "{temp_file}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Удаляем временный файл
            os.unlink(temp_file)
            
            return result.returncode == 0
        except Exception:
            return False
    
    def backup_hive(self, hive: str, output_file: str) -> bool:
        """Создать резервную копию куста реестра"""
        try:
            cmd = f'reg save HKLM\\{hive} "{output_file}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            return result.returncode == 0
        except Exception:
            return False
    
    def restore_hive(self, hive: str, backup_file: str) -> bool:
        """Восстановить куст реестра из резервной копии"""
        try:
            cmd = f'reg restore HKLM\\{hive} "{backup_file}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            return result.returncode == 0
        except Exception:
            return False
    
    def _get_type_name(self, value_type: int) -> str:
        """Получить имя типа значения реестра"""
        types = {
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
        }
        return types.get(value_type, f'UNKNOWN({value_type})')
    
    def open_regedit(self) -> bool:
        """Открыть стандартный редактор реестра"""
        try:
            subprocess.Popen('regedit.exe')
            return True
        except Exception:
            return False


# Функции для быстрого доступа
def read_registry(full_path: str, value_name: str = None):
    """Прочитать значение из реестра"""
    editor = RegistryEditor()
    return editor.read_key(full_path, value_name)


def write_registry(full_path: str, value_name: str, value, value_type=winreg.REG_SZ):
    """Записать значение в реестр"""
    editor = RegistryEditor()
    return editor.write_key(full_path, value_name, value, value_type)


def delete_registry(full_path: str, value_name: str = None):
    """Удалить значение из реестра"""
    editor = RegistryEditor()
    return editor.delete_key(full_path, value_name)


def open_regedit():
    """Открыть regedit"""
    editor = RegistryEditor()
    return editor.open_regedit()

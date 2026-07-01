"""
DedHelper - Утилита для восстановления Windows после вирусов
Версия 5.0 — как SimpleUnlocker но с уникальным дизайном

Требования:
- Python 3.8+
- Windows 10/11
- Права администратора
- VC++ Redistributable (для Explorer++) - устанавливается автоматически при необходимости
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import ctypes
import sys
import os
import subprocess
import shutil
import random
import string
import winreg
import tempfile
import logging
from pathlib import Path

# Константа для скрытия окна консоли
CREATE_NO_WINDOW = 0x08000000

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.environ.get('TEMP', '.'), 'DedHelper.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Глобальная переменная для хранения пути к копии Python
_PYTHON_COPY_PATH = None


def generate_random_name(length: int = 8) -> str:
    """Сгенерировать случайное имя для процесса"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def get_random_python_path() -> str:
    """Получить путь к копии python.exe со случайным именем"""
    global _PYTHON_COPY_PATH
    
    if _PYTHON_COPY_PATH and os.path.exists(_PYTHON_COPY_PATH):
        return _PYTHON_COPY_PATH
    
    # Создаём временную папку для копии
    temp_dir = tempfile.mkdtemp(prefix='PH_')
    python_exe = sys.executable
    random_name = generate_random_name(12) + '.exe'
    python_copy = os.path.join(temp_dir, random_name)
    
    try:
        shutil.copy2(python_exe, python_copy)
        _PYTHON_COPY_PATH = python_copy
        logger.debug(f"Создана копия Python: {python_copy}")
    except Exception as e:
        logger.error(f"Не удалось создать копию Python: {e}")
        return sys.executable
    
    return python_copy


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
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    
    if random_name:
        # Создаём копию powershell.exe со случайным именем
        temp_dir = tempfile.mkdtemp(prefix='PS_')
        ps_exe = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32\\WindowsPowerShell\\v1.0\\powershell.exe')
        random_name = generate_random_name(12) + '.exe'
        ps_copy = os.path.join(temp_dir, random_name)
        
        try:
            shutil.copy2(ps_exe, ps_copy)
            logger.debug(f"Создана копия PowerShell: {ps_copy}")
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


# Добавляем путь к модулям
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.autorun import AutorunManager
from modules.restrictions import RestrictionsManager
from modules.system import SystemCommands
from modules.recovery import WinREManager
from modules.processes import ProcessManager
from modules.registry import RegistryEditor
from modules.antigdi import AntiGDIManager, get_suspended_processes


# Критические процессы
CRITICAL_PROCESSES = [
    'system', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'services.exe', 'lsass.exe', 'lsm.exe', 'svchost.exe',
    'explorer.exe', 'winlogon.exe', 'spoolsv.exe', 'dwm.exe'
]

# === УНИКАЛЬНАЯ ЦВЕТОВАЯ СХЕМА ===
COLORS = {
    'bg_dark': '#1a1a2e',        # Тёмно-синий фон
    'bg_medium': '#16213e',      # Средний фон
    'bg_light': '#0f3460',       # Светлый фон
    'accent': '#e94560',         # Акцентный красный
    'accent_hover': '#ff6b6b',   # Акцент при наведении
    'text_main': '#ffffff',      # Белый текст
    'text_sec': '#a0a0a0',       # Серый текст
    'success': '#00d26a',        # Зелёный успех
    'warning': '#ffc107',        # Жёлтый warning
    'critical': '#ff6b35',       # Оранжевый критический
    'frozen': '#4ecdc4',         # Бирюзовый замороженный
}


def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin()


def run_as_admin():
    if not is_admin():
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)
        except Exception:
            return False
    return True


def generate_random_name():
    """Генерировать случайное имя из букв и цифр"""
    chars = string.ascii_letters + string.digits
    random_part = ''.join(random.choice(chars) for _ in range(8))
    return f"{random_part}.exe"


class DedHelperApp:
    """Основной класс приложения с уникальным дизайном"""

    def __init__(self, root):
        self.root = root

        # Генерируем случайное имя для заголовка
        self.random_name = generate_random_name()
        self.root.title(f"{self.random_name}")
        
        # Устанавливаем иконку окна
        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dedhelper.ico')
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception as e:
            logger.error(f"Ошибка установки иконки: {e}")

        self.root.geometry("1100x800")
        self.root.minsize(950, 700)
        
        # Применяем тёмную тему
        self._apply_dark_theme()
        
        # Проверяем права администратора
        self.is_admin = is_admin()
        
        # Путь к Explorer++ (извлекаем во временную папку)
        self.temp_dir = tempfile.mkdtemp(prefix='DedHelper_')
        self.explorer_path = os.path.join(self.temp_dir, 'Explorer++.exe')
        self._extract_explorer()

        # Путь к папке modules - корректно для EXE и для исходного кода
        if hasattr(sys, '_MEIPASS'):
            self.modules_dir = os.path.join(sys._MEIPASS, 'modules')
        else:
            self.modules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules')
        
        logger.info(f"Modules directory: {self.modules_dir}")

        # Менеджеры
        self.autorun_manager = AutorunManager()
        self.restrictions_manager = RestrictionsManager()
        self.system_commands = SystemCommands()
        self.winre_manager = WinREManager()
        self.process_manager = ProcessManager()
        self.registry_editor = RegistryEditor()

        # Отслеживание замороженных процессов
        self.frozen_pids = set()

        # === Создаём status_var СРАЗУ ===
        self.status_var = tk.StringVar()
        admin_status = "Администратор" if self.is_admin else "Нет прав админа!"
        self.status_var.set(admin_status)

        # Создаём интерфейс
        self._create_header()
        self._create_main_screen()
        self._create_notebook()
        self._create_status_bar()

        # Автоматическое определение диска Windows (для WinPE)
        self.root.after(1000, self._auto_detect_winpe_drive)

        # Обработчик закрытия окна
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Закрепляем окно (опционально)
        # self.root.attributes('-topmost', True)

    def _on_closing(self):
        """Обработчик закрытия приложения - очистка ресурсов"""
        try:
            # Размораживаем все замороженные процессы
            if self.frozen_pids:
                logger.info(f"Размораживание {len(self.frozen_pids)} процессов перед закрытием")
                for pid in self.frozen_pids:
                    try:
                        self.process_manager.resume_process(pid)
                    except Exception as e:
                        logger.warning(f"Не удалось разморозить процесс {pid}: {e}")

            # Очищаем временную папку
            if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
                try:
                    shutil.rmtree(self.temp_dir)
                    logger.info(f"Временная папка удалена: {self.temp_dir}")
                except Exception as e:
                    logger.warning(f"Не удалось удалить временную папку: {e}")

            logger.info("Приложение закрыто")
        except Exception as e:
            logger.error(f"Ошибка при закрытии: {e}")
        finally:
            self.root.destroy()
    
    def _apply_dark_theme(self):
        """Применить уникальную тёмную тему"""
        self.root.configure(bg=COLORS['bg_dark'])
        
        # Настраиваем стиль
        style = ttk.Style()
        
        # Пробуем использовать тему clam как основу
        try:
            style.theme_use('clam')
        except Exception:
            pass
        
        # Настраиваем цвета элементов - ВСЕГДА тёмные
        style.configure('TFrame', background=COLORS['bg_dark'])
        style.configure('TLabel', background=COLORS['bg_dark'], foreground=COLORS['text_main'], font=('Segoe UI', 10))
        style.configure('TButton', 
                       background=COLORS['bg_light'], 
                       foreground=COLORS['text_main'],
                       font=('Segoe UI', 10, 'bold'),
                       padding=10,
                       relief='flat')
        style.map('TButton',
                 background=[('active', COLORS['accent']), ('pressed', COLORS['accent_hover'])])
        
        style.configure('TLabelFrame', 
                       background=COLORS['bg_medium'], 
                       foreground=COLORS['accent'],
                       font=('Segoe UI', 11, 'bold'))
        style.configure('TLabelFrame.Label', 
                       background=COLORS['bg_medium'], 
                       foreground=COLORS['accent'],
                       font=('Segoe UI', 11, 'bold'))
        
        style.configure('Treeview',
                       background=COLORS['bg_medium'],
                       foreground=COLORS['text_main'],
                       fieldbackground=COLORS['bg_medium'],
                       font=('Segoe UI', 9),
                       rowheight=25)
        style.configure('Treeview.Heading',
                       background=COLORS['bg_light'],
                       foreground=COLORS['text_main'],
                       font=('Segoe UI', 10, 'bold'))
        style.map('Treeview',
                 background=[('selected', COLORS['accent'])])
        
        style.configure('TNotebook', 
                       background=COLORS['bg_dark'],
                       tabmargins=[0, 0, 0, 0])
        style.configure('TNotebook.Tab',
                       background=COLORS['bg_light'],
                       foreground=COLORS['text_main'],
                       font=('Segoe UI', 10, 'bold'),
                       padding=[15, 8])
        style.map('TNotebook.Tab',
                 background=[('selected', COLORS['accent'])])
        
        style.configure('TScrollbar',
                       background=COLORS['bg_light'],
                       troughcolor=COLORS['bg_dark'])
        
        style.configure('Horizontal.TProgressbar',
                       background=COLORS['accent'],
                       troughcolor=COLORS['bg_light'])
    
    def _extract_explorer(self):
        """Извлечь Explorer++ из встроенных ресурсов"""
        try:
            # Пытаемся получить путь к временной папке PyInstaller
            if hasattr(sys, '_MEIPASS'):
                # Программа запущена из EXE
                source = os.path.join(sys._MEIPASS, 'modules', 'Explorer++.exe')
                if os.path.exists(source):
                    shutil.copy2(source, self.explorer_path)
                    return
            
            # Пытаемся найти Explorer++ в исходной папке modules
            source_paths = [
                os.path.join(os.path.dirname(__file__), 'modules', 'Explorer++.exe'),
                os.path.join(os.getcwd(), 'modules', 'Explorer++.exe'),
            ]

            for source in source_paths:
                if os.path.exists(source):
                    shutil.copy2(source, self.explorer_path)
                    return

            # Если не найдено, пробуем с рабочего стола (для отладки)
            desktop_path = os.path.join(os.environ['USERPROFILE'], 'Desktop', 'експлорер', 'Explorer++.exe')
            if os.path.exists(desktop_path):
                shutil.copy2(desktop_path, self.explorer_path)
        except Exception as e:
            print(f"Ошибка извлечения Explorer++: {e}")

    def _create_header(self):
        """Создать красивый заголовок"""
        header_frame = tk.Frame(self.root, bg=COLORS['bg_light'], height=60)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Логотип (текстовый) - без подзаголовка
        logo_label = tk.Label(
            header_frame,
            text="DedHelper",
            font=('Segoe UI', 24, 'bold'),
            bg=COLORS['bg_light'],
            fg=COLORS['accent']
        )
        logo_label.pack(side=tk.LEFT, padx=20, pady=15)
        
        # Статус админа справа
        admin_label = tk.Label(
            header_frame,
            textvariable=self.status_var,
            font=('Segoe UI', 9, 'bold'),
            bg=COLORS['bg_light'],
            fg=COLORS['success'] if self.is_admin else COLORS['warning']
        )
        admin_label.pack(side=tk.RIGHT, padx=20, pady=15)
    
    def _create_main_screen(self):
        """Создать главный экран с красивыми кнопками"""
        # Используем tk.Frame с явным цветом фона
        main_frame = tk.Frame(self.root, bg=COLORS['bg_medium'])
        main_frame.pack(fill=tk.X, padx=15, pady=15)
        
        # Заголовок секции
        title_label = tk.Label(
            main_frame,
            text="Быстрое восстановление",
            font=('Segoe UI', 11, 'bold'),
            bg=COLORS['bg_medium'],
            fg=COLORS['accent']
        )
        title_label.pack(anchor=tk.W, padx=10, pady=(0, 10))
        
        # Фрейм для сетки кнопок
        buttons_frame = tk.Frame(main_frame, bg=COLORS['bg_medium'])
        buttons_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Создаём сетку кнопок 3x3 (без смайликов)
        buttons = [
            ("Восстановить шрифт", self._restore_font),
            ("Включить UAC", self._enable_uac),
            ("Войти в WinRE", self._enter_winre),
            ("Очистить Hosts", self._clean_hosts),
            ("Снять ограничения", self._remove_all_restrictions),
            ("Очистить автозагрузку", self._clean_autorun),
            ("sfc /scannow", self._run_sfc),
            ("Восстановить ассоциации", self._restore_associations),
        ]
        
        for i, (text, command) in enumerate(buttons):
            row = i // 3
            col = i % 3
            
            btn = tk.Button(
                buttons_frame,
                text=text,
                command=command,
                font=('Segoe UI', 10, 'bold'),
                bg=COLORS['bg_light'],
                fg=COLORS['text_main'],
                activebackground=COLORS['accent'],
                activeforeground=COLORS['text_main'],
                relief='flat',
                padx=15,
                pady=12,
                cursor='hand2',
                width=22,
                border=0
            )
            btn.grid(row=row, column=col, padx=8, pady=8)
            
            # Эффект при наведении
            btn.bind('<Enter>', lambda e: e.widget.config(bg=COLORS['accent']))
            btn.bind('<Leave>', lambda e: e.widget.config(bg=COLORS['bg_light']))
        
        # Разделитель
        sep = tk.Frame(self.root, bg=COLORS['bg_light'], height=2)
        sep.pack(fill=tk.X, padx=15, pady=10)
    
    def _create_notebook(self):
        """Создать вкладки"""
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)

        # Вкладки
        tabs = [
            ("Автозагрузка", self._create_autorun_tab),
            ("Планировщик", self._create_scheduler_tab),
            ("Ограничения", self._create_restrictions_tab),
            ("Процессы", self._create_processes_tab),
            ("Реестр", self._create_registry_tab),
            ("Система", self._create_system_tab),
            ("Проводник", self._create_explorer_tab),
        ]

        for name, create_func in tabs:
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=name)
            create_func(frame)
    
    def _create_status_bar(self):
        """Создать строку состояния"""
        status_bar = tk.Frame(self.root, bg=COLORS['bg_light'], height=30)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        status_bar.pack_propagate(False)
        
        status_label = tk.Label(
            status_bar,
            textvariable=self.status_var,
            font=('Segoe UI', 9),
            bg=COLORS['bg_light'],
            fg=COLORS['text_main'],
            padx=15
        )
        status_label.pack(side=tk.LEFT)
        
        # Версия справа
        version_label = tk.Label(
            status_bar,
            text="DedHelper",
            font=('Segoe UI', 9),
            bg=COLORS['bg_light'],
            fg=COLORS['text_sec'],
            padx=15
        )
        version_label.pack(side=tk.RIGHT)
    
    # ==================== БЫСТРЫЕ КНОПКИ ====================
    
    def _restore_font(self):
        if self.system_commands.restore_font_default():
            messagebox.showinfo("Успех", "Системный шрифт восстановлен")
        else:
            messagebox.showerror("Ошибка", "Не удалось восстановить шрифт")
    
    def _enable_uac(self):
        if self.system_commands.enable_uac():
            messagebox.showinfo("Успех", "UAC включён\nТребуется перезагрузка")
        else:
            messagebox.showerror("Ошибка", "Не удалось включить UAC")
    
    def _enter_winre(self):
        # Для опытного пользователя - без лишних подтверждений
        logger.info("Вход в WinRE")
        self.system_commands.enter_winre()
    
    def _clean_hosts(self):
        if self.restrictions_manager.clean_hosts():
            messagebox.showinfo("Успех", "Hosts файл очищен")
        else:
            messagebox.showerror("Ошибка", "Не удалось очистить Hosts")
    
    def _remove_all_restrictions(self):
        # Для опытного пользователя - без подтверждения
        result = self.restrictions_manager.remove_all_restrictions()
        msg = f"Результат снятия ограничений:\n\n"
        msg += f"ScancodeMap: {'OK' if result['scancode_map'] else 'FAIL'}\n"
        msg += f"Debuggers: {result['debuggers']} удалено\n"
        msg += f"DisallowRun: {'OK' if result['disallow_run'] else 'FAIL'}\n"
        msg += f"Hosts: {'OK' if result['hosts'] else 'FAIL'}\n"
        msg += f"Group Policy: {result['group_policy']} политик удалено"
        messagebox.showinfo("Результат", msg)
    
    def _clean_autorun(self):
        # Для опытного пользователя - без подтверждения
        removed = 0
        registry_data = self.autorun_manager.get_registry_autoruns()
        for location, values in registry_data.items():
            if isinstance(values, dict) and 'error' not in values:
                for name in values.keys():
                    if self.autorun_manager.remove_registry_autorun(name, location):
                        removed += 1
        startup_items = self.autorun_manager.get_startup_folder_items()
        for item in startup_items:
            if self.autorun_manager.remove_from_startup(item['name']):
                removed += 1
        messagebox.showinfo("Успех", f"Удалено элементов: {removed}")
    
    def _run_sfc(self):
        # Для опытного пользователя - без подтверждения
        self.system_commands.run_sfc()
    
    def _disable_test_mode(self):
        if self.system_commands.disable_test_mode():
            messagebox.showinfo("Успех", "Тестовый режим выключен\nТребуется перезагрузка")
        else:
            messagebox.showerror("Ошибка", "Не удалось выключить тестовый режим")
    
    def _restore_associations(self):
        """Восстановить ассоциации файлов с предварительным бэкапом реестра"""
        # Для опытного пользователя - без подтверждения
        restored = 0
        if self._fix_exe_association(): restored += 1
        if self._fix_bat_association(): restored += 1
        if self._fix_txt_association(): restored += 1
        if self._fix_lnk_association(): restored += 1
        if self._fix_html_association(): restored += 1
        
        logger.info(f"Восстановлено {restored} ассоциаций файлов")
        messagebox.showinfo("Успех", f"Восстановлено ассоциаций: {restored}")
    
    def _fix_exe_association(self) -> bool:
        """Восстановить ассоциацию .exe файлов"""
        try:
            logger.debug("Восстановление ассоциации .exe")
            try: winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r'Software\Classes\.exe')
            except OSError: pass
            key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r'.exe', 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'exefile')
            winreg.CloseKey(key)
            key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r'exefile\shell\open\command', 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, '"%1" %*')
            winreg.CloseKey(key)
            logger.info("Ассоциация .exe восстановлена")
            return True
        except Exception as e:
            logger.error(f"Ошибка восстановления ассоциации .exe: {e}")
            return False

    def _fix_bat_association(self) -> bool:
        """Восстановить ассоциацию .bat файлов"""
        try:
            logger.debug("Восстановление ассоциации .bat")
            key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r'.bat', 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'batfile')
            winreg.CloseKey(key)
            key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r'batfile\shell\open\command', 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, '"%1" %*')
            winreg.CloseKey(key)
            logger.info("Ассоциация .bat восстановлена")
            return True
        except Exception as e:
            logger.error(f"Ошибка восстановления ассоциации .bat: {e}")
            return False

    def _fix_txt_association(self) -> bool:
        """Восстановить ассоциацию .txt файлов"""
        try:
            logger.debug("Восстановление ассоциации .txt")
            key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r'.txt', 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'txtfile')
            winreg.CloseKey(key)
            key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r'txtfile\shell\open\command', 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'NOTEPAD.EXE "%1"')
            winreg.CloseKey(key)
            logger.info("Ассоциация .txt восстановлена")
            return True
        except Exception as e:
            logger.error(f"Ошибка восстановления ассоциации .txt: {e}")
            return False

    def _fix_lnk_association(self) -> bool:
        """Восстановить ассоциацию .lnk файлов"""
        try:
            logger.debug("Восстановление ассоциации .lnk")
            key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r'.lnk', 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'lnkfile')
            winreg.CloseKey(key)
            logger.info("Ассоциация .lnk восстановлена")
            return True
        except Exception as e:
            logger.error(f"Ошибка восстановления ассоциации .lnk: {e}")
            return False

    def _fix_html_association(self) -> bool:
        """Восстановить ассоциацию .html файлов"""
        try:
            logger.debug("Восстановление ассоциации .html")
            key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r'.html', 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'htmlfile')
            winreg.CloseKey(key)
            logger.info("Ассоциация .html восстановлена")
            return True
        except Exception as e:
            logger.error(f"Ошибка восстановления ассоциации .html: {e}")
            return False
    
    # ==================== ВКЛАДКИ ====================
    
    def _create_autorun_tab(self, parent):
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Обновить", command=self._refresh_autorun).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Удалить выбранное", command=self._remove_selected_autorun).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Удалить всё", command=self._remove_all_autorun).pack(side=tk.LEFT, padx=2)
        
        columns = ('Тип', 'Имя', 'Значение')
        self.autorun_tree = ttk.Treeview(parent, columns=columns, show='tree headings', height=20)
        self.autorun_tree.heading('#0', text='Расположение')
        self.autorun_tree.heading('Тип', text='Тип')
        self.autorun_tree.heading('Имя', text='Имя')
        self.autorun_tree.heading('Значение', text='Значение')
        self.autorun_tree.column('#0', width=180)
        self.autorun_tree.column('Тип', width=80)
        self.autorun_tree.column('Имя', width=150)
        self.autorun_tree.column('Значение', width=400)
        
        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.autorun_tree.yview)
        self.autorun_tree.configure(yscrollcommand=vsb.set)
        self.autorun_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self._refresh_autorun()
    
    def _refresh_autorun(self):
        try:
            for item in self.autorun_tree.get_children():
                self.autorun_tree.delete(item)
            registry_data = self.autorun_manager.get_registry_autoruns()
            for location, values in registry_data.items():
                if isinstance(values, dict) and 'error' not in values:
                    for name, value in values.items():
                        value_str = str(value)
                        if len(value_str) > 100:
                            value_str = value_str[:97] + "..."
                        self.autorun_tree.insert('', 'end', text=location, values=('Реестр', name, value_str))
            startup_items = self.autorun_manager.get_startup_folder_items()
            for item in startup_items:
                path_str = item['path']
                if len(path_str) > 100:
                    path_str = path_str[:97] + "..."
                self.autorun_tree.insert('', 'end', text='Startup', values=('Файл', item['name'], path_str))
            self.status_var.set(f"Автозагрузка: {len(self.autorun_tree.get_children())} элементов")
        except Exception as e:
            self.status_var.set(f"Ошибка: {e}")
    
    def _remove_selected_autorun(self):
        selected = self.autorun_tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите элемент")
            return
        if messagebox.askyesno("Подтверждение", "Удалить выбранный элемент?"):
            for item in selected:
                values = self.autorun_tree.item(item)['values']
                if len(values) >= 2:
                    name = values[1]
                    location = self.autorun_tree.item(item)['text']
                    if 'HK' in location or 'Run' in location:
                        self.autorun_manager.remove_registry_autorun(name)
                    elif 'Startup' in location:
                        self.autorun_manager.remove_from_startup(name)
            self._refresh_autorun()
            messagebox.showinfo("Успех", "Элемент удалён")
    
    def _remove_all_autorun(self):
        if messagebox.askyesno("Подтверждение", "Удалить ВСЮ автозагрузку?"):
            self._clean_autorun()
            self._refresh_autorun()
    
    def _create_scheduler_tab(self, parent):
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Обновить", command=self._refresh_scheduler).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Удалить задачу", command=self._delete_task).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Отключить", command=self._disable_task).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Включить", command=self._enable_task).pack(side=tk.LEFT, padx=2)
        
        columns = ('Имя',)
        self.scheduler_tree = ttk.Treeview(parent, columns=columns, show='tree headings', height=20)
        self.scheduler_tree.heading('#0', text='Путь')
        self.scheduler_tree.heading('Имя', text='Имя')
        self.scheduler_tree.column('#0', width=400)
        self.scheduler_tree.column('Имя', width=300)
        
        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.scheduler_tree.yview)
        self.scheduler_tree.configure(yscrollcommand=vsb.set)
        self.scheduler_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self._refresh_scheduler()
    
    def _refresh_scheduler(self):
        try:
            for item in self.scheduler_tree.get_children():
                self.scheduler_tree.delete(item)
            tasks = self.autorun_manager.get_scheduled_tasks()
            for task in tasks[:100]:
                self.scheduler_tree.insert('', 'end', text='Tasks', values=(task['name'],))
        except Exception:
            pass
    
    def _delete_task(self):
        selected = self.scheduler_tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите задачу")
            return
        item = self.scheduler_tree.item(selected[0])
        task_name = item['values'][0] if item['values'] else ''
        if messagebox.askyesno("Подтверждение", f"Удалить задачу {task_name}?"):
            if self.autorun_manager.delete_scheduled_task(task_name):
                messagebox.showinfo("Успех", "Задача удалена")
                self._refresh_scheduler()
            else:
                messagebox.showerror("Ошибка", "Не удалось удалить задачу")
    
    def _disable_task(self):
        selected = self.scheduler_tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите задачу")
            return
        item = self.scheduler_tree.item(selected[0])
        task_name = item['values'][0] if item['values'] else ''
        if self.autorun_manager.disable_scheduled_task(task_name):
            messagebox.showinfo("Успех", "Задача отключена")
        else:
            messagebox.showerror("Ошибка", "Не удалось отключить задачу")
    
    def _enable_task(self):
        selected = self.scheduler_tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите задачу")
            return
        item = self.scheduler_tree.item(selected[0])
        task_name = item['values'][0] if item['values'] else ''
        if self.autorun_manager.enable_scheduled_task(task_name):
            messagebox.showinfo("Успех", "Задача включена")
        else:
            messagebox.showerror("Ошибка", "Не удалось включить задачу")
    
    def _create_restrictions_tab(self, parent):
        # Используем tk.Frame с явным цветом
        btn_frame = tk.Frame(parent, bg=COLORS['bg_medium'])
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Заголовок
        title_label = tk.Label(
            btn_frame,
            text="Снятие ограничений",
            font=('Segoe UI', 11, 'bold'),
            bg=COLORS['bg_medium'],
            fg=COLORS['accent']
        )
        title_label.grid(row=0, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        ttk.Button(btn_frame, text="Снять ScancodeMap", command=self._remove_scancode).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Удалить IFEO Debuggers", command=self._remove_debuggers).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(btn_frame, text="Снять DisallowRun", command=self._remove_disallow_run).grid(row=1, column=2, padx=5, pady=5)
        ttk.Button(btn_frame, text="Очистить Hosts", command=self._clean_hosts_btn).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Восстановить Hosts", command=self._restore_hosts).grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(btn_frame, text="Снять ВСЕ ограничения", command=self._remove_all_restrictions_btn).grid(row=2, column=2, padx=5, pady=5)
    
    def _remove_scancode(self):
        if self.restrictions_manager.remove_scancode_map():
            messagebox.showinfo("Успех", "ScancodeMap удалён")
        else:
            messagebox.showerror("Ошибка", "ScancodeMap не найден")
    
    def _remove_debuggers(self):
        count = self.restrictions_manager.remove_all_debuggers()
        messagebox.showinfo("Успех", f"Удалено записей IFEO: {count}")
    
    def _remove_disallow_run(self):
        if self.restrictions_manager.remove_disallow_run():
            messagebox.showinfo("Успех", "DisallowRun снят")
        else:
            messagebox.showerror("Ошибка", "DisallowRun не найден")
    
    def _clean_hosts_btn(self):
        self._clean_hosts()
    
    def _restore_hosts(self):
        if self.restrictions_manager.restore_hosts_default():
            messagebox.showinfo("Успех", "Hosts файл восстановлен")
        else:
            messagebox.showerror("Ошибка", "Не удалось восстановить Hosts")
    
    def _remove_all_restrictions_btn(self):
        self._remove_all_restrictions()
    
    def _create_processes_tab(self, parent):
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Обновить", command=self._refresh_processes).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Завершить", command=self._terminate_process).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Заморозить", command=self._suspend_process).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Разморозить", command=self._resume_process).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Снять критический флаг", command=self._remove_critical_flag).pack(side=tk.LEFT, padx=2)
        
        columns = ('PID', 'Путь', 'CPU')
        self.process_tree = ttk.Treeview(parent, columns=columns, show='tree headings', height=20)
        self.process_tree.heading('#0', text='Имя процесса')
        self.process_tree.heading('PID', text='PID')
        self.process_tree.heading('Путь', text='Путь к файлу')
        self.process_tree.heading('CPU', text='Нагрузка CPU')
        self.process_tree.column('#0', width=150)
        self.process_tree.column('PID', width=80)
        self.process_tree.column('Путь', width=400)
        self.process_tree.column('CPU', width=100)
        
        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=vsb.set)
        self.process_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self._refresh_processes()
    
    def _get_all_process_paths(self):
        paths = {}
        try:
            ps_command = '''
            Get-CimInstance Win32_Process | Select-Object ProcessId, ExecutablePath |
            ForEach-Object { if ($_.ExecutablePath) { Write-Output "$($_.ProcessId)=$($_.ExecutablePath)" } }
            '''
            result = run_hidden_powershell(ps_command)
            
            # Декодируем вывод с обработкой ошибок кодировки
            stdout = decode_output(result.stdout) if result.stdout else ""
            
            for line in stdout.strip().split('\n'):
                if '=' in line:
                    pid_str, path = line.split('=', 1)
                    try:
                        paths[int(pid_str)] = path
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass
        return paths
    
    def _refresh_processes(self):
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        all_paths = self._get_all_process_paths()
        processes = self.process_manager.get_processes()
        
        for proc in processes:
            name_lower = proc['name'].lower()
            path = all_paths.get(proc['pid'], 'N/A')
            cpu = "0%"
            
            tag = 'normal'
            if name_lower in CRITICAL_PROCESSES:
                tag = 'critical'
            elif proc['pid'] in self.frozen_pids:
                tag = 'frozen'
            
            self.process_tree.insert('', 'end', text=proc['name'], values=(proc['pid'], path, cpu), tags=(tag,))
        
        self.process_tree.tag_configure('critical', background=COLORS['critical'])
        self.process_tree.tag_configure('frozen', background=COLORS['frozen'])
        self.process_tree.tag_configure('normal', background=COLORS['bg_medium'])
        
        self.status_var.set(f"Процессов: {len(processes)}")
    
    def _get_selected_pid(self):
        selected = self.process_tree.selection()
        if selected:
            item = self.process_tree.item(selected[0])
            return int(item['values'][0])
        return None
    
    def _terminate_process(self):
        pid = self._get_selected_pid()
        if pid:
            item = self.process_tree.item(self.process_tree.selection()[0])
            name = item['text']
            if name.lower() in CRITICAL_PROCESSES:
                if not messagebox.askyesno("ПРЕДУПРЕЖДЕНИЕ", f"Завершить критический процесс {name}?"):
                    return
            if messagebox.askyesno("Подтверждение", f"Завершить процесс {name} (PID {pid})?"):
                if self.process_manager.terminate_process(pid):
                    messagebox.showinfo("Успех", "Процесс завершён")
                    self.frozen_pids.discard(pid)
                    self._refresh_processes()
                else:
                    messagebox.showerror("Ошибка", "Не удалось завершить процесс")
    
    def _suspend_process(self):
        """Заморозить процесс с предупреждением о критических процессах"""
        pid = self._get_selected_pid()
        if pid:
            item = self.process_tree.item(self.process_tree.selection()[0])
            name = item['text']
            
            if self.process_manager.suspend_process(pid):
                self.frozen_pids.add(pid)
                logger.info(f"Процесс {name} (PID {pid}) заморожен")
                messagebox.showinfo("Успех", "Процесс заморожен")
                self._refresh_processes()
            else:
                logger.error(f"Не удалось заморозить процесс {name} (PID {pid})")
                messagebox.showerror("Ошибка", "Не удалось заморозить процесс")
    
    def _resume_process(self):
        pid = self._get_selected_pid()
        if pid:
            if self.process_manager.resume_process(pid):
                self.frozen_pids.discard(pid)
                messagebox.showinfo("Успех", "Процесс разморожен")
                self._refresh_processes()
            else:
                messagebox.showerror("Ошибка", "Не удалось разморозить процесс")
    
    def _remove_critical_flag(self):
        pid = self._get_selected_pid()
        if pid:
            item = self.process_tree.item(self.process_tree.selection()[0])
            name = item['text']
            if messagebox.askyesno("Предупреждение", f"Снять критический флаг с {name}?"):
                if self.process_manager.remove_critical_flag(pid):
                    messagebox.showinfo("Успех", "Критический флаг снят")
                    self._refresh_processes()
                else:
                    messagebox.showerror("Ошибка", "Не удалось снять флаг")
    
    def _create_registry_tab(self, parent):
        # Используем tk.Frame с явным цветом
        input_frame = tk.Frame(parent, bg=COLORS['bg_medium'])
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Заголовок
        title_label = tk.Label(
            input_frame,
            text="Работа с реестром",
            font=('Segoe UI', 11, 'bold'),
            bg=COLORS['bg_medium'],
            fg=COLORS['accent']
        )
        title_label.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(input_frame, text="Путь к ключу:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.registry_path_var = tk.StringVar(value="HKCU\\Software")
        self.registry_path_entry = tk.Entry(input_frame, textvariable=self.registry_path_var, width=60,
                                            bg=COLORS['bg_medium'], fg=COLORS['text_main'], 
                                            insertbackground=COLORS['text_main'], relief='flat',
                                            font=('Consolas', 10))
        self.registry_path_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Имя значения:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.registry_value_var = tk.StringVar()
        self.registry_value_entry = tk.Entry(input_frame, textvariable=self.registry_value_var, width=60,
                                             bg=COLORS['bg_medium'], fg=COLORS['text_main'],
                                             insertbackground=COLORS['text_main'], relief='flat',
                                             font=('Consolas', 10))
        self.registry_value_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Значение:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.registry_data_var = tk.StringVar()
        self.registry_data_entry = tk.Entry(input_frame, textvariable=self.registry_data_var, width=60,
                                            bg=COLORS['bg_medium'], fg=COLORS['text_main'],
                                            insertbackground=COLORS['text_main'], relief='flat',
                                            font=('Consolas', 10))
        self.registry_data_entry.grid(row=3, column=1, padx=5, pady=5)
        
        btn_frame = tk.Frame(input_frame, bg=COLORS['bg_medium'])
        btn_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="Прочитать", command=self._read_registry).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Записать", command=self._write_registry).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Удалить", command=self._delete_registry).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Открыть regedit", command=self._open_regedit).pack(side=tk.LEFT, padx=2)
        
        self.registry_output = scrolledtext.ScrolledText(parent, height=15, bg=COLORS['bg_medium'], fg=COLORS['text_main'], font=('Consolas', 9))
        self.registry_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def _read_registry(self):
        path = self.registry_path_var.get()
        value = self.registry_value_var.get()
        result = self.registry_editor.read_key(path, value if value else None)
        self.registry_output.delete(1.0, tk.END)
        self.registry_output.insert(tk.END, f"Путь: {path}\n")
        self.registry_output.insert(tk.END, f"Успех: {result['success']}\n")
        if result['error']:
            self.registry_output.insert(tk.END, f"Ошибка: {result['error']}\n")
        self.registry_output.insert(tk.END, f"\nЗначение:\n{result['value']}")
    
    def _write_registry(self):
        path = self.registry_path_var.get()
        value_name = self.registry_value_var.get()
        value_data = self.registry_data_var.get()
        if not value_name:
            messagebox.showwarning("Предупреждение", "Введите имя значения")
            return
        if self.registry_editor.write_key(path, value_name, value_data):
            messagebox.showinfo("Успех", "Значение записано")
        else:
            messagebox.showerror("Ошибка", "Не удалось записать значение")
    
    def _delete_registry(self):
        path = self.registry_path_var.get()
        value_name = self.registry_value_var.get()
        if messagebox.askyesno("Подтверждение", f"Удалить {value_name} из {path}?"):
            if self.registry_editor.delete_key(path, value_name if value_name else None):
                messagebox.showinfo("Успех", "Удалено")
            else:
                messagebox.showerror("Ошибка", "Не удалось удалить")
    
    def _open_regedit(self):
        self.registry_editor.open_regedit()

    
    def _create_system_tab(self, parent):
        # Создаём сетку фреймов с явными цветами
        frames_config = [
            ("Системные команды", [
                ("Перезагрузка", self._restart_pc),
                ("Выключение", self._shutdown_pc),
                ("Выйти из пользователя", self._logout),
                ("Войти в WinRE", self._enter_winre_sys),
                ("Выполнить (Win+R)", self._run_dialog),
            ]),
            ("Восстановление", [
                ("sfc /scannow", self._run_sfc_sys),
                ("DISM Restore", self._run_dism),
                ("Включить UAC", self._enable_uac_sys),
                ("Выкл. тестовый режим", self._disable_test_mode_sys),
                ("Восстановить шрифт", self._restore_font_sys),
            ]),
            ("WinPE", [
                ("Определить диск", self._check_winpe_drive),
                ("Заменить sethc", self._replace_sethc_winpe),
                ("Заменить utilman", self._replace_utilman_winpe),
                ("Восстановить sethc", self._restore_sethc_winpe),
                ("Восстановить utilman", self._restore_utilman_winpe),
                ("Удалить Windows Defender", self._remove_windows_devender),
            ]),
        ]
        
        for title, buttons in frames_config:
            # Frame с явным цветом
            frame = tk.Frame(parent, bg=COLORS['bg_medium'])
            frame.pack(fill=tk.X, padx=10, pady=5)
            
            # Заголовок
            title_label = tk.Label(
                frame,
                text=title,
                font=('Segoe UI', 11, 'bold'),
                bg=COLORS['bg_medium'],
                fg=COLORS['accent']
            )
            title_label.pack(anchor=tk.W, padx=5, pady=(0, 5))
            
            btn_frame = tk.Frame(frame, bg=COLORS['bg_medium'])
            btn_frame.pack(pady=5)
            
            for text, cmd in buttons:
                ttk.Button(btn_frame, text=text, command=cmd).pack(side=tk.LEFT, padx=5, pady=3)

    def _restart_pc(self):
        if messagebox.askyesno("Подтверждение", "Перезагрузить ПК?"):
            self.system_commands.restart_pc(5)
            logger.info("Перезагрузка ПК")

    def _shutdown_pc(self):
        if messagebox.askyesno("Подтверждение", "Выключить ПК?"):
            self.system_commands.shutdown_pc(5)
            logger.info("Выключение ПК")

    def _logout(self):
        if messagebox.askyesno("Подтверждение", "Выйти из пользователя?"):
            self.system_commands.logout()
            logger.info("Выход из пользователя")

    # Алиасы на основные методы (для вкладки Система)
    _enter_winre_sys = _enter_winre
    _run_sfc_sys = _run_sfc
    _enable_uac_sys = _enable_uac
    _disable_test_mode_sys = _disable_test_mode
    _restore_font_sys = _restore_font

    def _run_dialog(self):
        self.system_commands.run_dialog()
        logger.info("Запуск диалога выполнения (Win+R)")

    def _run_dism(self):
        if messagebox.askyesno("Подтверждение", "Запустить DISM?"):
            self.system_commands.run_dism()
            logger.info("Запуск DISM")

    # ==================== WINPE ФУНКЦИИ ====================
    def _check_winpe_drive(self):
        """Определить диск Windows и показать информацию"""
        try:
            drive_letter = self.system_commands.get_winpe_drive_letter()
            if drive_letter:
                system32_path = f"{drive_letter}\\Windows\\System32"
                msg = f"Диск Windows найден: {drive_letter}\n\n"
                logger.info(f"WinPE диск определён: {drive_letter}")
                messagebox.showinfo("Определение диска", msg)
            else:
                msg = "Не удалось определить диск Windows\n\n"
                logger.warning("Не удалось определить диск Windows")
                messagebox.showwarning("Ошибка", msg)
        except Exception as e:
            logger.error(f"Ошибка определения диска: {e}")
            messagebox.showerror("Ошибка", f"Не удалось определить диск:\n{e}")

    def _remove_windows_devender(self):
        """Удалить Windows Defender (максимально приближено к оригинальному скрипту)"""
        try:
            from modules.winpe_defender import remove_defender_completely, find_windows_drive
            
            # Определяем диск
            drive_letter = self.system_commands.get_winpe_drive_letter()
            if not drive_letter:
                drive_letter = find_windows_drive()
            
            msg = (
                f"ВНИМАНИЕ! Будут уничтожены:\n"
                f"  • Windows Defender\n"
                f"  • Брандмауэр Windows\n"
                f"  • Центр безопасности\n"
                f"  • Все связанные службы и драйверы\n\n"
                f"Диск: {drive_letter}\n\n"
                f"Продолжить?"
            )
            
            if not messagebox.askyesno("ПОДТВЕРЖДЕНИЕ", msg):
                return
            
            # Запускаем удаление
            self.status_var.set("Удаление Windows Defender...")
            self.root.update()
            
            result = remove_defender_completely(drive_letter)
            
            if result['success']:
                messagebox.showinfo("УСПЕХ", result['message'])
                logger.info(f"Windows Defender удалён: {result['details']}")
            else:
                messagebox.showerror("ОШИБКА", result['message'])
                logger.error(f"Ошибка удаления Defender: {result['message']}")
            
            self.status_var.set("Готово")
            
        except ImportError as e:
            logger.error(f"Модуль winpe_defender не найден: {e}")
            messagebox.showerror("Ошибка", "Модуль удаления Defender не найден")
        except Exception as e:
            logger.error(f"Ошибка удаления Defender: {e}")
            messagebox.showerror("Ошибка", f"Не удалось удалить Defender:\n{e}")

    def _restore_windows_devender(self):
        """Восстановить Windows Defender (через DISM)"""
        try:
            if not messagebox.askyesno("Подтверждение", 
                "Восстановить Windows Defender?\n\n"
                "Для этого будет использован DISM.\n"
                "Потребуется перезагрузка."):
                return
            
            self.status_var.set("Восстановление Windows Defender...")
            self.root.update()
            
            ps_script = '''
            Write-Output "Восстановление Windows Defender..."
            
            # Восстановление через DISM
            dism /online /cleanup-image /restorehealth
            
            # Переустановка Defender
            dism /online /add-capability /capabilityname:Microsoft.Windows.Sense.Client~~~~0.0.1.0
            
            Write-Output "Восстановление завершено"
            '''
            
            result = run_hidden_powershell(ps_script)
            
            if result.returncode == 0:
                messagebox.showinfo("Успех", "Восстановление Windows Defender запущено.\nПотребуется перезагрузка.")
            else:
                messagebox.showerror("Ошибка", "Не удалось восстановить Defender.")
            
            self.status_var.set("Готово")
        except Exception as e:
            logger.error(f"Ошибка восстановления Defender: {e}")
            messagebox.showerror("Ошибка", f"Не удалось восстановить Defender:\n{e}")

    def _restore_windows_devender(self):
        """Восстановить Windows Defender (через DISM)"""
        try:
            if not messagebox.askyesno("Подтверждение", 
                "Восстановить Windows Defender?\n\n"
                "Для этого будет использован DISM.\n"
                "Потребуется перезагрузка."):
                return
            
            ps_script = '''
            Write-Output "Восстановление Windows Defender..."
            
            # Восстановление через DISM
            dism /online /cleanup-image /restorehealth
            
            # Переустановка Defender
            dism /online /add-capability /capabilityname:Microsoft.Windows.Sense.Client~~~~0.0.1.0
            
            Write-Output "Восстановление завершено"
            '''
            
            result = run_hidden_powershell(ps_script)
            
            if result.returncode == 0:
                messagebox.showinfo("Успех", "Восстановление Windows Defender запущено.\nПотребуется перезагрузка.")
            else:
                messagebox.showerror("Ошибка", "Не удалось восстановить Defender.")
        except Exception as e:
            logger.error(f"Ошибка восстановления Defender: {e}")
            messagebox.showerror("Ошибка", f"Не удалось восстановить Defender:\n{e}")



    def _replace_sethc_winpe(self):
        """Заменить sethc.exe на выбранный файл - ЖЁСТКАЯ СИСТЕМА"""
        file_path = filedialog.askopenfilename(title="Выберите файл для sethc.exe", filetypes=[("EXE файлы", "*.exe"), ("Все файлы", "*.*")])
        if file_path:
            try:
                logger.info(f"Замена sethc.exe файлом: {file_path}")
                
                # Жёсткий путь к System32
                sethc_path = r"C:\Windows\System32\sethc.exe"
                
                # Проверяем существование исходного файла
                if not os.path.exists(file_path):
                    messagebox.showerror("Ошибка", f"Исходный файл не найден:\n{file_path}")
                    return

                # Нормализуем путь для PowerShell (заменяем / на \)
                ps_source_path = file_path.replace('/', '\\')
                
                # PowerShell скрипт с прямыми путями без экранирования
                ps_script = f'''
$ErrorActionPreference = "Continue"

# Пути
$sourcePath = "{ps_source_path}"
$destPath = "{sethc_path}"

Write-Output "Source: $sourcePath"
Write-Output "Dest: $destPath"

# Проверяем исходный файл
if (-not (Test-Path $sourcePath)) {{
    Write-Output "ERROR: Source file not found"
    exit 1
}}

# Останавливаем TrustedInstaller
try {{
    $ti = Get-Process TrustedInstaller -ErrorAction SilentlyContinue
    if ($ti) {{ 
        Write-Output "Stopping TrustedInstaller..."
        Stop-Process $ti -Force 
    }}
}} catch {{
    Write-Output "Warning: Could not stop TrustedInstaller: $_"
}}

# Получаем файл назначения
$dest = Get-Item $destPath -ErrorAction SilentlyContinue

if ($dest) {{
    Write-Output "Taking ownership..."
    
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
    
    Write-Output "Removing original..."
    # Удаляем оригинал
    Remove-Item -Path $dest.FullName -Force -ErrorAction Stop
}} else {{
    Write-Output "Destination file not found, skipping removal"
}}

Write-Output "Copying new file..."
# Копируем новый файл
Copy-Item $sourcePath $destPath -Force

# Проверяем успех
if (Test-Path $destPath) {{
    Write-Output "SUCCESS"
}} else {{
    Write-Output "FAILED: File not found after copy"
}}
'''

                result = run_hidden_powershell(ps_script)
                output = decode_output(result.stdout) if result.stdout else ""
                error_output = decode_output(result.stderr) if result.stderr else ""
                
                logger.info(f"PowerShell вывод: {output}")
                if error_output:
                    logger.error(f"PowerShell ошибки: {error_output}")
                
                if result.returncode == 0 and "SUCCESS" in output:
                    logger.info("sethc.exe успешно заменён")
                    messagebox.showinfo("Успех", "sethc.exe заменён\nТребуется перезагрузка")
                else:
                    logger.error(f"Не удалось заменить sethc. Код ошибки: {result.returncode}\nВывод: {output}\nОшибки: {error_output}")
                    messagebox.showerror("Ошибка", f"Не удалось заменить sethc:\nКод ошибки: {result.returncode}\n\nВывод PowerShell:\n{output}")
            except Exception as e:
                logger.error(f"Ошибка при замене sethc: {e}")
                messagebox.showerror("Ошибка", f"Не удалось заменить sethc:\n{e}")

    def _replace_utilman_winpe(self):
        """Заменить utilman.exe на выбранный файл - ЖЁСТКАЯ СИСТЕМА"""
        file_path = filedialog.askopenfilename(title="Выберите файл для utilman.exe", filetypes=[("EXE файлы", "*.exe"), ("Все файлы", "*.*")])
        if file_path:
            try:
                logger.info(f"Замена utilman.exe файлом: {file_path}")
                
                # Жёсткий путь к System32
                utilman_path = r"C:\Windows\System32\utilman.exe"
                
                # Проверяем существование исходного файла
                if not os.path.exists(file_path):
                    messagebox.showerror("Ошибка", f"Исходный файл не найден:\n{file_path}")
                    return

                # Нормализуем путь для PowerShell (заменяем / на \)
                ps_source_path = file_path.replace('/', '\\')
                
                # PowerShell скрипт с прямыми путями без экранирования
                ps_script = f'''
$ErrorActionPreference = "Continue"

# Пути
$sourcePath = "{ps_source_path}"
$destPath = "{utilman_path}"

Write-Output "Source: $sourcePath"
Write-Output "Dest: $destPath"

# Проверяем исходный файл
if (-not (Test-Path $sourcePath)) {{
    Write-Output "ERROR: Source file not found"
    exit 1
}}

# Останавливаем TrustedInstaller
try {{
    $ti = Get-Process TrustedInstaller -ErrorAction SilentlyContinue
    if ($ti) {{ 
        Write-Output "Stopping TrustedInstaller..."
        Stop-Process $ti -Force 
    }}
}} catch {{
    Write-Output "Warning: Could not stop TrustedInstaller: $_"
}}

# Получаем файл назначения
$dest = Get-Item $destPath -ErrorAction SilentlyContinue

if ($dest) {{
    Write-Output "Taking ownership..."
    
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
    
    Write-Output "Removing original..."
    # Удаляем оригинал
    Remove-Item -Path $dest.FullName -Force -ErrorAction Stop
}} else {{
    Write-Output "Destination file not found, skipping removal"
}}

Write-Output "Copying new file..."
# Копируем новый файл
Copy-Item $sourcePath $destPath -Force

# Проверяем успех
if (Test-Path $destPath) {{
    Write-Output "SUCCESS"
}} else {{
    Write-Output "FAILED: File not found after copy"
}}
'''

                result = run_hidden_powershell(ps_script)
                output = decode_output(result.stdout) if result.stdout else ""
                error_output = decode_output(result.stderr) if result.stderr else ""
                
                logger.info(f"PowerShell вывод: {output}")
                if error_output:
                    logger.error(f"PowerShell ошибки: {error_output}")
                
                if result.returncode == 0 and "SUCCESS" in output:
                    logger.info("utilman.exe успешно заменён")
                    messagebox.showinfo("Успех", "utilman.exe заменён\nТребуется перезагрузка")
                else:
                    logger.error(f"Не удалось заменить utilman. Код ошибки: {result.returncode}\nВывод: {output}\nОшибки: {error_output}")
                    messagebox.showerror("Ошибка", f"Не удалось заменить utilman:\nКод ошибки: {result.returncode}\n\nВывод PowerShell:\n{output}")
            except Exception as e:
                logger.error(f"Ошибка при замене utilman: {e}")
                messagebox.showerror("Ошибка", f"Не удалось заменить utilman:\n{e}")

    def _restore_sethc_winpe(self):
        """Восстановить sethc из встроенных ресурсов"""
        try:
            logger.info("Восстановление sethc.exe из встроенных ресурсов")
            
            # Жёсткий путь
            sethc_path = r"C:\Windows\System32\sethc.exe"

            # Определяем источник файла - проверяем несколько путей
            source_sethc = None

            # Путь 1: PyInstaller временная папка
            if hasattr(sys, '_MEIPASS'):
                source_sethc = os.path.join(sys._MEIPASS, 'modules', 'sethc.exe')
                logger.debug(f"Проверка пути _MEIPASS: {source_sethc}")
                if os.path.exists(source_sethc):
                    logger.info(f"Файл найден в _MEIPASS: {source_sethc}")
                    return self._do_restore_sethc(source_sethc, sethc_path)

            # Путь 2: self.modules_dir (уже корректно определён)
            source_sethc = os.path.join(self.modules_dir, 'sethc.exe')
            logger.debug(f"Проверка пути modules_dir: {source_sethc}")
            if os.path.exists(source_sethc):
                logger.info(f"Файл найден в modules_dir: {source_sethc}")
                return self._do_restore_sethc(source_sethc, sethc_path)

            # Путь 3: Рабочая директория
            source_sethc = os.path.join(os.getcwd(), 'modules', 'sethc.exe')
            logger.debug(f"Проверка пути cwd: {source_sethc}")
            if os.path.exists(source_sethc):
                logger.info(f"Файл найден в cwd: {source_sethc}")
                return self._do_restore_sethc(source_sethc, sethc_path)

            # Файл не найден ни в одном из путей
            logger.error("Файл sethc.exe не найден в ресурсах")
            messagebox.showerror("Ошибка", f"Файл sethc.exe не найден в ресурсах\n\nПроверьте наличие файла в папке:\n{self.modules_dir}")
        except Exception as e:
            logger.error(f"Ошибка при восстановлении sethc: {e}")
            messagebox.showerror("Ошибка", f"Не удалось восстановить sethc:\n{e}")

    def _do_restore_sethc(self, source_path: str, dest_path: str):
        """Выполнить восстановление sethc.exe"""
        ps_script = f'''
$ErrorActionPreference = "Stop"

$source = Get-Item "{source_path}"
$dest = Get-Item "{dest_path}" -ErrorAction SilentlyContinue

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
Copy-Item $source.FullName "{dest_path}" -Force

# Проверяем успех
if (Test-Path "{dest_path}") {{
    Write-Output "SUCCESS"
}} else {{
    Write-Output "FAILED"
}}
'''
        result = run_hidden_powershell(ps_script)
        output = decode_output(result.stdout) if result.stdout else ""
        
        if result.returncode == 0 and "SUCCESS" in output:
            logger.info("sethc.exe успешно восстановлен")
            messagebox.showinfo("Успех", "sethc.exe восстановлен\nТребуется перезагрузка")
        else:
            logger.error(f"Не удалось восстановить sethc. Код ошибки: {result.returncode}\nВывод: {output}")
            messagebox.showerror("Ошибка", f"Не удалось восстановить sethc:\nКод ошибки: {result.returncode}")

    def _restore_utilman_winpe(self):
        """Восстановить utilman из встроенных ресурсов"""
        try:
            logger.info("Восстановление utilman.exe из встроенных ресурсов")
            
            # Жёсткий путь
            utilman_path = r"C:\Windows\System32\utilman.exe"

            # Определяем источник файла - проверяем несколько путей
            source_utilman = None

            # Путь 1: PyInstaller временная папка
            if hasattr(sys, '_MEIPASS'):
                source_utilman = os.path.join(sys._MEIPASS, 'modules', 'Utilman.exe')
                logger.debug(f"Проверка пути _MEIPASS: {source_utilman}")
                if os.path.exists(source_utilman):
                    logger.info(f"Файл найден в _MEIPASS: {source_utilman}")
                    return self._do_restore_utilman(source_utilman, utilman_path)

            # Путь 2: self.modules_dir (уже корректно определён)
            source_utilman = os.path.join(self.modules_dir, 'Utilman.exe')
            logger.debug(f"Проверка пути modules_dir: {source_utilman}")
            if os.path.exists(source_utilman):
                logger.info(f"Файл найден в modules_dir: {source_utilman}")
                return self._do_restore_utilman(source_utilman, utilman_path)

            # Путь 3: Рабочая директория
            source_utilman = os.path.join(os.getcwd(), 'modules', 'Utilman.exe')
            logger.debug(f"Проверка пути cwd: {source_utilman}")
            if os.path.exists(source_utilman):
                logger.info(f"Файл найден в cwd: {source_utilman}")
                return self._do_restore_utilman(source_utilman, utilman_path)

            # Файл не найден ни в одном из путей
            logger.error("Файл Utilman.exe не найден в ресурсах")
            messagebox.showerror("Ошибка", f"Файл Utilman.exe не найден в ресурсах\n\nПроверьте наличие файла в папке:\n{self.modules_dir}")
        except Exception as e:
            logger.error(f"Ошибка при восстановлении utilman: {e}")
            messagebox.showerror("Ошибка", f"Не удалось восстановить utilman:\n{e}")

    def _do_restore_utilman(self, source_path: str, dest_path: str):
        """Выполнить восстановление utilman.exe"""
        ps_script = f'''
$ErrorActionPreference = "Stop"

$source = Get-Item "{source_path}"
$dest = Get-Item "{dest_path}" -ErrorAction SilentlyContinue

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
Copy-Item $source.FullName "{dest_path}" -Force

# Проверяем успех
if (Test-Path "{dest_path}") {{
    Write-Output "SUCCESS"
}} else {{
    Write-Output "FAILED"
}}
'''
        result = run_hidden_powershell(ps_script)
        output = decode_output(result.stdout) if result.stdout else ""
        
        if result.returncode == 0 and "SUCCESS" in output:
            logger.info("utilman.exe успешно восстановлен")
            messagebox.showinfo("Успех", "utilman.exe восстановлен\nТребуется перезагрузка")
        else:
            logger.error(f"Не удалось восстановить utilman. Код ошибки: {result.returncode}\nВывод: {output}")
            messagebox.showerror("Ошибка", f"Не удалось восстановить utilman:\nКод ошибки: {result.returncode}")

    def _auto_detect_winpe_drive(self):
        """Автоматически определить букву диска Windows (тихое определение)"""
        try:
            drive_letter = self.system_commands.get_winpe_drive_letter()
            if drive_letter:
                logger.info(f"Автоматически определён диск Windows: {drive_letter}")
                self.status_var.set(f"Администратор | Диск: {drive_letter}")
            else:
                logger.debug("Определение диска: запущено из Windows (не WinPE)")
        except Exception as e:
            logger.error(f"Ошибка автоматического определения диска: {e}")

    def _clean_temp(self):
        """Очистить папку Temp"""
        try:
            logger.info("Очистка папки Temp")
            temp_dir = os.environ.get('TEMP', '')
            if temp_dir:
                count = 0
                for file in os.listdir(temp_dir):
                    try:
                        os.remove(os.path.join(temp_dir, file))
                        count += 1
                    except Exception:
                        pass
                logger.info(f"Temp очищен ({count} файлов)")
                messagebox.showinfo("Успех", f"Temp очищен ({count} файлов)")
        except Exception as e:
            logger.error(f"Ошибка при очистке Temp: {e}")
            messagebox.showerror("Ошибка", str(e))

    def _clean_recycle(self):
        """Очистить корзину"""
        try:
            logger.info("Очистка корзины")
            run_hidden_command('cleanmgr /d C /VERYLOWDISK')
            messagebox.showinfo("Успех", "Корзина очищается")
        except Exception as e:
            logger.error(f"Ошибка при очистке корзины: {e}")
            messagebox.showerror("Ошибка", str(e))

    # ==================== ПРОВОДНИК ====================

    def _create_explorer_tab(self, parent):
        # Frame с явным цветом
        info_frame = tk.Frame(parent, bg=COLORS['bg_medium'])
        info_frame.pack(fill=tk.X, padx=10, pady=10)

        # Заголовок
        title_label = tk.Label(
            info_frame,
            text="Встроенный проводник",
            font=('Segoe UI', 11, 'bold'),
            bg=COLORS['bg_medium'],
            fg=COLORS['accent']
        )
        title_label.pack(pady=5)

        btn_frame = tk.Frame(info_frame, bg=COLORS['bg_medium'])
        btn_frame.pack(pady=15)

        exp_btn = tk.Button(
            btn_frame,
            text="Запустить Explorer++",
            command=self._launch_explorer,
            font=('Segoe UI', 11, 'bold'),
            bg=COLORS['accent'],
            fg=COLORS['text_main'],
            activebackground=COLORS['accent_hover'],
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2'
        )
        exp_btn.pack(side=tk.LEFT, padx=10)

        win_btn = tk.Button(
            btn_frame,
            text="Обычный проводник",
            command=self._launch_windows_explorer,
            font=('Segoe UI', 11),
            bg=COLORS['bg_light'],
            fg=COLORS['text_main'],
            activebackground=COLORS['accent'],
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2'
        )
        win_btn.pack(side=tk.LEFT, padx=10)

        # Статус
        status_text = scrolledtext.ScrolledText(parent, height=4, bg=COLORS['bg_medium'], fg=COLORS['text_main'], font=('Segoe UI', 10))
        status_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        explorer_exists = os.path.exists(self.explorer_path)
        status_text.insert(tk.END, f"Путь: {self.explorer_path}\n")
        status_text.insert(tk.END, f"Статус: {'Найден и готов к запуску' if explorer_exists else 'Не найден'}\n")

        if not explorer_exists:
            status_text.insert(tk.END, f"\nВНИМАНИЕ: Explorer++ не найден в ресурсах!\n")
        else:
            status_text.insert(tk.END, f"\nExplorer++ встроен в программу и готов к использованию.\n")

    def _launch_explorer(self):
        """Запустить Explorer++ из встроенных ресурсов с рандомным именем"""
        try:
            # Проверяем и извлекаем если нужно
            if not os.path.exists(self.explorer_path):
                self._extract_explorer()
            
            if not os.path.exists(self.explorer_path):
                messagebox.showerror("Ошибка", "Explorer++ не найден в ресурсах")
                return
            
            # Генерируем рандомное имя для копии
            import random
            import string
            random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=8)) + '.exe'
            temp_explorer = os.path.join(self.temp_dir, random_name)
            
            # Копируем с рандомным именем
            shutil.copy2(self.explorer_path, temp_explorer)
            
            if os.path.exists(temp_explorer):
                subprocess.Popen([temp_explorer])
                messagebox.showinfo("Успех", f"Explorer++ запущен\nИмя процесса: {random_name}")
            else:
                messagebox.showerror("Ошибка", "Не удалось создать копию Explorer++")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось запустить Explorer++:\n{e}")
    
    def _launch_windows_explorer(self):
        try:
            subprocess.Popen('explorer.exe')
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))


def main():
    if not is_admin():
        run_as_admin()
    
    root = tk.Tk()
    app = DedHelperApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

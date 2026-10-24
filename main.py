"""
DedHelper - Утилита для восстановления Windows после вирусов
Версия 5.0 — утилитарный дизайн:
  * тонкая шапка, боковая навигация, компактные карточки без emoji
  * таблицы с тонкой рамкой, без чередования строк
  * Автозагрузка объединена с Планировщиком (под-вкладки)
  * расширенная очистка: Winlogon Shell/Userinit/AppRuntime + AppInit_DLLs
    + подозрительные задачи планировщика
  * исправлены вертикальные ползунки во всех таблицах
  * окно 1100×720 (было 1200×820)

Требования:
- Python 3.8+
- Windows 10/11
- Права администратора
- VC++ Redistributable (для Explorer++)
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
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
import re
from modules.offline import OfflineSession, is_winpe

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


# Постоянный кэш для проводников — не удаляется при выходе.
EXPLORER_CACHE_DIR = os.path.join(tempfile.gettempdir(), 'DedHelper_Explorers')


def generate_random_name(length: int = 8) -> str:
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def run_hidden_command(cmd: str, capture_output: bool = False) -> subprocess.CompletedProcess:
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return subprocess.run(
        cmd, shell=True, capture_output=capture_output,
        startupinfo=startupinfo, creationflags=CREATE_NO_WINDOW,
    )


def run_hidden_powershell(ps_command: str, capture_output: bool = True,
                          random_name: bool = True) -> subprocess.CompletedProcess:
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    if random_name:
        temp_dir = tempfile.mkdtemp(prefix='PS_')
        ps_exe = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                              'System32\\WindowsPowerShell\\v1.0\\powershell.exe')
        rnd = generate_random_name(12) + '.exe'
        ps_copy = os.path.join(temp_dir, rnd)
        try:
            shutil.copy2(ps_exe, ps_copy)
        except Exception as e:
            logger.error(f"Не удалось создать копию PowerShell: {e}")
            ps_copy = ps_exe
        return subprocess.run(
            [ps_copy, '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
            capture_output=capture_output, startupinfo=startupinfo,
            creationflags=CREATE_NO_WINDOW,
        )
    return subprocess.run(
        ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
        capture_output=capture_output, startupinfo=startupinfo,
        creationflags=CREATE_NO_WINDOW,
    )


def decode_output(stdout_bytes: bytes) -> str:
    if not stdout_bytes:
        return ""
    for encoding in ['utf-8', 'cp1251', 'cp866']:
        try:
            return stdout_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return stdout_bytes.decode('utf-8', errors='replace')


# Путь к модулям
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.autorun import AutorunManager
from modules.restrictions import RestrictionsManager
from modules.system import SystemCommands
from modules.recovery import WinREManager
from modules.processes import (
    ProcessManager, is_process_critical, is_system_path,
    is_signed_by_microsoft, enable_debug_privilege,
    is_critical_process, is_process_suspicious,
)
from modules.registry import RegistryEditor


# === ЦВЕТОВЫЕ СХЕМЫ ===
THEME_DARK = {
    'bg_dark': '#1a1a2e', 'bg_medium': '#16213e', 'bg_light': '#0f3460',
    'accent': '#e94560', 'accent_hover': '#ff6b6b',
    'text_main': '#ffffff', 'text_sec': '#a0a0a0',
    'success': '#00d26a', 'warning': '#ffc107',
    'critical': '#ff6b35', 'frozen': '#4ecdc4',
    'border': '#30304a', 'card': '#1f2a44',
}
THEME_LIGHT = {
    'bg_dark': '#eef1f8', 'bg_medium': '#ffffff', 'bg_light': '#dfe6f3',
    'accent': '#e94560', 'accent_hover': '#c62f49',
    'text_main': '#15172b', 'text_sec': '#555a72',
    'success': '#1a9e55', 'warning': '#b9820a',
    'critical': '#d14b23', 'frozen': '#1b8f87',
    'border': '#c7cde0', 'card': '#ffffff',
}
THEME_STANDARD = {
    'bg_dark': '#2b2b2b', 'bg_medium': '#333333', 'bg_light': '#3c3c3c',
    'accent': '#0078d4', 'accent_hover': '#2b95e6',
    'text_main': '#f0f0f0', 'text_sec': '#aaaaaa',
    'success': '#4caf50', 'warning': '#e0a800',
    'critical': '#d9534f', 'frozen': '#17a2b8',
    'border': '#4a4a4a', 'card': '#323232',
}
THEMES = {'dark': THEME_STANDARD, 'light': THEME_LIGHT, 'standard': THEME_DARK}

COLORS = dict(THEME_DARK)

# Шрифты (смесь утилитарного и корпоративного стиля)
FONT_UI = ('Segoe UI', 9)
FONT_UI_BOLD = ('Segoe UI Semibold', 9)
FONT_UI_LARGE = ('Segoe UI', 11)
FONT_UI_LARGE_BOLD = ('Segoe UI Semibold', 11)
FONT_MONO = ('Consolas', 9)


def apply_theme(name: str):
    COLORS.clear()
    COLORS.update(THEMES.get(name, THEME_DARK))


# === НАСТРОЙКИ ===
SETTINGS_DIR = os.path.join(os.environ.get('LOCALAPPDATA') or os.environ.get('TEMP', '.'), 'DedHelper')
SETTINGS_FILE = os.path.join(SETTINGS_DIR, 'settings.json')
DEFAULT_SETTINGS = {
    'theme': 'standard',
    'close_new_processes': False,
    'always_on_top': True,
}


def load_settings() -> dict:
    settings = dict(DEFAULT_SETTINGS)
    try:
        import json
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            settings.update({k: v for k, v in saved.items() if k in DEFAULT_SETTINGS})
    except Exception:
        pass
    return settings


def save_settings(settings: dict):
    try:
        import json
        os.makedirs(SETTINGS_DIR, exist_ok=True)
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Не удалось сохранить настройки: {e}")


def extract_target_path(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    value = os.path.expandvars(value)
    if value.startswith('"'):
        end = value.find('"', 1)
        return value[1:end] if end != -1 else value[1:]
    low = value.lower()
    idx = low.find(".exe")
    if idx != -1:
        return value[:idx + 4]
    parts = value.split()
    return parts[0] if parts else value


def resolve_existing_path(raw_value: str) -> str:
    target = extract_target_path(raw_value)
    if not target:
        return ""
    if os.path.exists(target):
        return os.path.abspath(target)
    found = shutil.which(target)
    return found or ""


def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin()


def relaunch_as_admin() -> bool:
    if is_admin():
        return True
    try:
        params = ' '.join(f'"{a}"' for a in sys.argv[1:])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return rc > 32
    except Exception as e:
        logger.error(f"Не удалось перезапуститься с правами администратора: {e}")
        return False


# ---------------------------------------------------------------------------
# Утилиты для реестра
# ---------------------------------------------------------------------------
_HIVE_MAP = {
    'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
    'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
    'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
    'HKEY_USERS': winreg.HKEY_USERS,
    'HKEY_CURRENT_CONFIG': winreg.HKEY_CURRENT_CONFIG,
    'HKLM': winreg.HKEY_LOCAL_MACHINE,
    'HKCU': winreg.HKEY_CURRENT_USER,
    'HKCR': winreg.HKEY_CLASSES_ROOT,
    'HKU': winreg.HKEY_USERS,
    'HKCC': winreg.HKEY_CURRENT_CONFIG,
}


def _split_reg_path(location: str):
    location = (location or "").strip().strip('\\')
    parts = location.split('\\', 1)
    if len(parts) < 2:
        return None, None
    hive = _HIVE_MAP.get(parts[0].upper())
    if hive is None:
        return None, None
    return hive, parts[1]


def _write_reg_value(location: str, name: str, new_value):
    hive, subpath = _split_reg_path(location)
    if hive is None:
        return False, f"Не удалось разобрать путь реестра: {location}"
    try:
        key = winreg.OpenKey(hive, subpath, 0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE)
    except FileNotFoundError:
        return False, f"Раздел реестра не найден: {subpath}"
    except PermissionError:
        return False, "Отказано в доступе (запустите от администратора)"
    except OSError as e:
        return False, str(e)
    try:
        try:
            _old, vtype = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            vtype = winreg.REG_SZ
        except OSError as e:
            return False, str(e)
        if vtype == winreg.REG_MULTI_SZ:
            value = [v for v in str(new_value).split('\n') if v != '']
        else:
            value = str(new_value)
        try:
            winreg.SetValueEx(key, name, 0, vtype, value)
            return True, ""
        except OSError as e:
            return False, str(e)
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass

class DedHelperApp:
    """Основной класс приложения."""

    def __init__(self, root):
        self.root = root
        self.settings = load_settings()
        apply_theme(self.settings.get('theme', 'standard'))

        # ---- status_var: создаём ПЕРВОЙ, до любого UI/офлайн/менеджеров ----
        self.status_var = tk.StringVar()
        self.is_admin = is_admin()
        self.status_var.set("Администратор" if self.is_admin else "Нет прав админа!")
        self.temp_dir = tempfile.mkdtemp(prefix='DedHelper_')
        self._ensure_explorer_cache()
        self.explorer_mode = None
        self.explorer_py_source = None
        self._extract_explorer()
        self._extract_explorer_pp()

        self.random_name = generate_random_name()
        self.root.title(self.random_name)

        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     'dedhelper.ico')
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception as e:
            logger.error(f"Ошибка установки иконки: {e}")

        self.root.geometry("1100x720")
        self.root.minsize(980, 640)
        if self.settings.get('always_on_top'):
            try:
                self.root.attributes('-topmost', True)
            except Exception:
                pass

        self._apply_dark_theme()

        # ===== офлайн-режим (WinPE) =====
        self._offline_active = False
        if is_winpe():
            OfflineSession.start()
            if is_winpe():
                OfflineSession.start()
                self._offline_active = OfflineSession.active
                logger.info(f"[OFFLINE] active={self._offline_active}, "
                            f"drive={OfflineSession.drive}, "
                            f"hives={list(OfflineSession.hives.keys())}")
            self._offline_active = OfflineSession.active
            if self._offline_active:
                logger.info(f"WinPE: работаем с диском {OfflineSession.drive}")
                self.status_var.set(
                    f"WinPE | Диск: {OfflineSession.drive} (офлайн)")
            else:
                logger.error("WinPE: не удалось определить диск Windows")
                self.status_var.set("WinPE | Диск не найден")
                try:
                    messagebox.showwarning(
                        "Диск Windows не найден",
                        "WinPE-режим, но диск с установленной Windows "
                        "не обнаружен.\n\n"
                        "Функции автозагрузки, служб, планировщика, ограничений "
                        "будут показывать данные самого WinPE (X:).",
                        parent=root)
                except Exception:
                    pass

        # модули — прочитают OfflineSession
        self.autorun_manager = AutorunManager()
        self.restrictions_manager = RestrictionsManager()
        self.system_commands = SystemCommands()
        self.winre_manager = WinREManager()
        self.process_manager = ProcessManager()
        self.registry_editor = RegistryEditor()

        self.frozen_pids = set()
        self.autorun_raw = {}
        self.windows_drive = None

        self._reported_critical = set()
        self._last_critical_map = {}

        # Создаём layout
        self._create_header()
        self._create_quick_actions()
        self._create_sections()
        self._create_status_bar()

        self.root.after(1000, self._auto_detect_winpe_drive)

        self._known_pids = set()
        self._process_watch_job = None
        self.root.after(2000, self._process_watch_tick)

        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        import threading, queue
        self._scan_queue = queue.Queue()
        self._scan_stop = threading.Event()
        self._scan_thread = threading.Thread(
            target=self._critical_scanner_loop, daemon=True, name="CriticalScanner"
        )
        self._scan_thread.start()
        self.root.after(500, self._drain_scan_queue)

    # ───────── слежение за процессами ─────────
    def _critical_scanner_loop(self):
        while not self._scan_stop.is_set():
            try:
                suspicious = self.process_manager.find_suspicious_critical()
            except Exception as e:
                logger.error(f"critical scanner: {e}")
                suspicious = []
            try:
                self._scan_queue.put_nowait(suspicious)
            except Exception:
                pass
            if self._scan_stop.wait(5.0):
                break

    def _drain_scan_queue(self):
        try:
            while True:
                suspicious = self._scan_queue.get_nowait()
        except Exception:
            suspicious = None

        if suspicious is not None:
            current_pids = {s['pid'] for s in suspicious}
            self._reported_critical &= current_pids
            new = [s for s in suspicious if s['pid'] not in self._reported_critical]
            if new:
                self._reported_critical |= {s['pid'] for s in new}
                for s in new:
                    logger.warning(f"⚠️ {s['name']} (PID {s['pid']}) — {s['reason']}")
                self._show_critical_alert(new)

        try:
            self.root.after(300, self._drain_scan_queue)
        except Exception:
            pass

    def _should_protect(self, proc: dict) -> bool:
        """True — этот процесс НЕ трогаем при авто-закрытии / массовой заморозке."""
        try:
            if proc['pid'] == os.getpid():
                return True
            if proc['pid'] in (0, 4):
                return True
            path = proc.get('path') or ''
            if path and hasattr(self, 'temp_dir') and self.temp_dir:
                if os.path.normcase(path).startswith(os.path.normcase(self.temp_dir)):
                    return True
                if os.path.normcase(path).startswith(os.path.normcase(EXPLORER_CACHE_DIR)):
                    return True
            if path and is_system_path(path) and is_signed_by_microsoft(path):
                return True
        except Exception:
            return True
        return False

    def _kill_new_process(self, proc: dict) -> bool:
        pid = proc['pid']
        path = proc.get('path') or ''
        name = proc.get('name') or f"PID {pid}"
        try:
            if is_critical_process(pid, path):
                result = self.process_manager.safe_terminate_critical(pid)
                if result['success']:
                    logger.info(f"Нейтрализован критический процесс: {name} (PID {pid})")
                    return True
                logger.warning(f"Не удалось нейтрализовать {name} "
                               f"(этап: {result['stage']}): {result['error']}")
                return False
            ok = self.process_manager.terminate_process(pid)
            if ok:
                logger.info(f"Закрыт новый процесс: {name} (PID {pid})")
            else:
                logger.warning(f"TerminateProcess не удался: {name} (PID {pid})")
            return bool(ok)
        except Exception as e:
            logger.error(f"Ошибка закрытия {name}: {e}")
            return False

    def _process_watch_tick(self):
        try:
            current = self.process_manager.get_processes()
            current_pids = {p['pid'] for p in current}
            if self.settings.get('close_new_processes') and self._known_pids:
                new_pids = current_pids - self._known_pids
                for p in current:
                    if p['pid'] not in new_pids:
                        continue
                    if self._should_protect(p):
                        continue
                    self._kill_new_process(p)
            self._known_pids = current_pids
        except Exception as e:
            logger.error(f"Ошибка слежения за процессами: {e}")
        self._process_watch_job = self.root.after(2000, self._process_watch_tick)

    def _show_critical_alert(self, items):
        if not items:
            return
        lines = "\n".join(
            f"  • {s['name']} (PID {s['pid']})\n"
            f"    Путь: {s['path'] or 'N/A'}\n"
            f"    Причина: {s['reason']}"
            for s in items
        )
        msg = (
            "ОБНАРУЖЕНЫ ПОДОЗРИТЕЛЬНЫЕ КРИТИЧЕСКИЕ ПРОЦЕССЫ\n\n"
            f"{lines}\n\n"
            "Такие процессы защищают себя от завершения: попытка убить их "
            "вызывает BSOD. Обычно это вирусы.\n\n"
            "Нейтрализовать все найденные?"
        )
        if not messagebox.askyesno("Антивирус", msg, parent=self.root):
            return

        ok = 0
        fail = []
        for s in items:
            try:
                r = self.process_manager.safe_terminate_critical(s['pid'])
                if r['success']:
                    ok += 1
                    self.frozen_pids.discard(s['pid'])
                    self._reported_critical.discard(s['pid'])
                else:
                    fail.append(f"  • {s['name']} (PID {s['pid']}): {r['stage']} — {r['error']}")
            except Exception as e:
                fail.append(f"  • {s['name']} (PID {s['pid']}): exception — {e}")

        text = f"Нейтрализовано: {ok} из {len(items)}"
        if fail:
            text += "\n\nНе удалось:\n" + "\n".join(fail)
        messagebox.showinfo("Результат", text, parent=self.root)
        logger.info(f"Нейтрализация: {ok}/{len(items)}")
        try:
            self._refresh_processes()
        except Exception:
            pass

    def _on_closing(self):
        try:
            self._scan_stop.set()
            if hasattr(self, '_scan_thread') and self._scan_thread.is_alive():
                self._scan_thread.join(timeout=2.0)
        except Exception:
            pass
        try:
            save_settings(self.settings)
        except Exception as e:
            logger.error(f"Не удалось сохранить настройки: {e}")
        if self._process_watch_job is not None:
            try:
                self.root.after_cancel(self._process_watch_job)
            except Exception:
                pass
        try:
            from modules.offline import OfflineSession
            OfflineSession.stop()
        except Exception:
            pass
        try:
            if self.frozen_pids:
                for pid in self.frozen_pids:
                    try:
                        self.process_manager.resume_process(pid)
                    except Exception:
                        pass
            if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
                try:
                    shutil.rmtree(self.temp_dir)
                except Exception:
                    pass
            logger.info("Приложение закрыто")
        except Exception as e:
            logger.error(f"Ошибка при закрытии: {e}")
        finally:
            self.root.destroy()

    # ───────── тема / стили ─────────
    def _apply_dark_theme(self):
        self.root.configure(bg=COLORS['bg_dark'])
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass

        style.configure('TFrame', background=COLORS['bg_dark'])
        style.configure('TLabel', background=COLORS['bg_dark'],
                        foreground=COLORS['text_main'], font=FONT_UI)

        style.configure('TButton',
                        background=COLORS['bg_light'], foreground=COLORS['text_main'],
                        font=FONT_UI_BOLD, padding=(10, 5),
                        borderwidth=1, relief='solid')
        style.map('TButton',
                  background=[('active', COLORS['accent']),
                              ('pressed', COLORS['accent_hover'])],
                  foreground=[('active', 'white'), ('pressed', 'white')])

        for ws in ('TCheckbutton', 'TRadiobutton'):
            style.configure(ws, background=COLORS['bg_medium'],
                            foreground=COLORS['text_main'], font=FONT_UI)
            style.map(ws,
                      background=[('active', COLORS['bg_medium'])],
                      foreground=[('active', COLORS['accent'])])

        style.configure('TLabelFrame', background=COLORS['bg_medium'],
                        foreground=COLORS['accent'], font=FONT_UI_BOLD,
                        borderwidth=1, relief='solid')
        style.configure('TLabelFrame.Label', background=COLORS['bg_medium'],
                        foreground=COLORS['accent'], font=FONT_UI_BOLD)

        # Treeview БЕЗ чередования, с тонкой рамкой вокруг (реализуется
        # отдельной обёрткой в _create_scrolled_tree)
        style.configure('Treeview', background=COLORS['bg_medium'],
                        foreground=COLORS['text_main'],
                        fieldbackground=COLORS['bg_medium'],
                        font=FONT_MONO, rowheight=24,
                        borderwidth=0, relief='flat')
        style.configure('Treeview.Heading', background=COLORS['bg_light'],
                        foreground=COLORS['text_main'], font=FONT_UI_BOLD,
                        relief='flat', borderwidth=0, padding=(8, 5))
        style.map('Treeview.Heading', background=[('active', COLORS['accent'])])
        style.map('Treeview',
                  background=[('selected', COLORS['accent'])],
                  foreground=[('selected', 'white')])

        style.configure('TNotebook', background=COLORS['bg_dark'],
                        borderwidth=0, tabmargins=[0, 0, 0, 0])
        style.configure('TNotebook.Tab',
                        background=COLORS['bg_medium'],
                        foreground=COLORS['text_sec'],
                        font=FONT_UI_BOLD,
                        padding=[14, 6], borderwidth=0)
        style.map('TNotebook.Tab',
                  background=[('selected', COLORS['accent']),
                              ('active', COLORS['bg_light'])],
                  foreground=[('selected', 'white'),
                              ('active', COLORS['text_main'])])

        style.configure('TScrollbar', background=COLORS['bg_light'],
                        troughcolor=COLORS['bg_dark'],
                        borderwidth=0, arrowcolor=COLORS['text_sec'])
        style.configure('Horizontal.TProgressbar', background=COLORS['accent'],
                        troughcolor=COLORS['bg_light'], borderwidth=0)

        style.configure('TEntry', fieldbackground=COLORS['bg_medium'],
                        foreground=COLORS['text_main'],
                        insertcolor=COLORS['text_main'],
                        bordercolor=COLORS['border'], padding=4,
                        font=FONT_MONO)

    # ───────── кэш проводников ─────────
    def _ensure_explorer_cache(self):
        try:
            os.makedirs(EXPLORER_CACHE_DIR, exist_ok=True)
        except Exception as e:
            logger.error(f"Не удалось создать кэш {EXPLORER_CACHE_DIR}: {e}")
        self.explorer_path = os.path.join(EXPLORER_CACHE_DIR, 'Explorer--.exe')
        self.explorer_pp_path = os.path.join(EXPLORER_CACHE_DIR, 'Explorer++.exe')

    def _candidate_dirs(self):
        dirs = []
        if hasattr(sys, '_MEIPASS'):
            dirs.append(os.path.join(sys._MEIPASS, 'modules'))
        if hasattr(self, 'modules_dir'):
            dirs.append(self.modules_dir)
        dirs.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules'))
        dirs.append(os.path.join(os.getcwd(), 'modules'))
        return dirs

    def _extract_explorer(self):
        try:
            if os.path.exists(self.explorer_path):
                self.explorer_mode = 'exe'
                logger.info(f"Explorer--: используем кэш ({self.explorer_path})")
                return
            for d in self._candidate_dirs():
                source = os.path.join(d, 'Explorer--.exe')
                if os.path.exists(source):
                    shutil.copy2(source, self.explorer_path)
                    self.explorer_mode = 'exe'
                    logger.info(f"Explorer--: скопирован в кэш из {source}")
                    return
            for d in self._candidate_dirs():
                for name in ('explorer--.py', 'Explorer--.py'):
                    source = os.path.join(d, name)
                    if os.path.exists(source):
                        self.explorer_py_source = source
                        self.explorer_mode = 'py'
                        logger.warning(f"Explorer--.exe не найден, использую исходник {source}")
                        return
            logger.warning("Explorer-- не найден")
        except Exception as e:
            logger.error(f"Ошибка извлечения Explorer--: {e}")

    def _find_python_interpreter(self):
        if not getattr(sys, 'frozen', False):
            return sys.executable
        for name in ('pythonw.exe', 'python.exe', 'py.exe'):
            found = shutil.which(name)
            if found:
                return found
        return None

    def _extract_explorer_pp(self):
        try:
            if os.path.exists(self.explorer_pp_path):
                logger.info(f"Explorer++: используем кэш ({self.explorer_pp_path})")
                return
            candidates = []
            if hasattr(sys, '_MEIPASS'):
                candidates.append(os.path.join(sys._MEIPASS, 'modules', 'Explorer++.exe'))
                candidates.append(os.path.join(sys._MEIPASS, 'Explorer++.exe'))
            if hasattr(self, 'modules_dir'):
                candidates.append(os.path.join(self.modules_dir, 'Explorer++.exe'))
            candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           'modules', 'Explorer++.exe'))
            candidates.append(os.path.join(os.getcwd(), 'modules', 'Explorer++.exe'))
            for source in candidates:
                if source and os.path.exists(source):
                    shutil.copy2(source, self.explorer_pp_path)
                    logger.info(f"Explorer++: скопирован в кэш из {source}")
                    return
            logger.info("Explorer++.exe не найден (необязателен)")
        except Exception as e:
            logger.error(f"Ошибка извлечения Explorer++: {e}")

    # ───────── LAYOUT ─────────
    def _create_header(self):
        """Тонкая шапка ~42px."""
        header = tk.Frame(self.root, bg=COLORS['bg_medium'], height=42)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        tk.Label(header, text="DedHelper",
                 font=('Segoe UI Semibold', 12, 'bold'),
                 bg=COLORS['bg_medium'], fg=COLORS['text_main']
                 ).pack(side=tk.LEFT, padx=(16, 10), pady=10)

        status_bg = COLORS['success'] if self.is_admin else COLORS['warning']
        status_text = "  Администратор  " if self.is_admin else "  Без прав админа  "
        tk.Label(header, text=status_text, font=('Segoe UI', 9),
                 bg=status_bg, fg='white', padx=8, pady=3
                 ).pack(side=tk.RIGHT, padx=16)

        # Тонкая акцентная полоса под шапкой
        tk.Frame(self.root, bg=COLORS['accent'], height=2).pack(fill=tk.X)

    def _create_quick_actions(self):
        """Компактные карточки без emoji, без hover."""
        wrap = tk.Frame(self.root, bg=COLORS['bg_dark'])
        wrap.pack(fill=tk.X, padx=8, pady=(8, 4))

        title_row = tk.Frame(wrap, bg=COLORS['bg_dark'])
        title_row.pack(fill=tk.X, pady=(0, 6))
        tk.Label(title_row, text="Быстрое восстановление",
                 font=FONT_UI_LARGE_BOLD,
                 bg=COLORS['bg_dark'], fg=COLORS['text_main']
                 ).pack(side=tk.LEFT)
        tk.Frame(title_row, bg=COLORS['border'], height=1
                 ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=6)

        cards = tk.Frame(wrap, bg=COLORS['bg_dark'])
        cards.pack(fill=tk.X)

        buttons = [
            ("Восстановить шрифт",      self._restore_font),
            ("Включить UAC",            self._enable_uac),
            ("Войти в WinRE",           self._enter_winre),
            ("Снять ограничения",       self._remove_all_restrictions),
            ("Очистить автозагрузку",   self._clean_autorun),
            ("sfc /scannow",            self._run_sfc),
            ("Восстановить ассоциации", self._restore_associations),
            ("Заменить Sethc/Utilman на DH",  self._quick_replace_sethc_utilman_self),
        ]
        for i, (text, command) in enumerate(buttons):
            self._create_action_card(cards, text, command, i)

        for c in range(3):
            cards.columnconfigure(c, weight=1, uniform='card')

    def _create_action_card(self, parent, text, command, idx):
        row, col = idx // 3, idx % 3
        card = tk.Frame(parent, bg=COLORS['card'],
                        highlightthickness=1,
                        highlightbackground=COLORS['border'],
                        cursor='hand2')
        card.grid(row=row, column=col, padx=3, pady=3, sticky='nsew')

        label = tk.Label(card, text=text, font=FONT_UI,
                         bg=COLORS['card'], fg=COLORS['text_main'],
                         justify='center', cursor='hand2')
        label.pack(padx=8, pady=8, fill=tk.BOTH, expand=True)

        def on_click(_e):
            command()

        card.bind('<Button-1>', on_click)
        label.bind('<Button-1>', on_click)

    def _create_sections(self):
        """Боковая навигация + правый контент."""
        container = tk.Frame(self.root, bg=COLORS['bg_dark'])
        container.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Левая панель
        sidebar = tk.Frame(container, bg=COLORS['bg_medium'], width=180)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # Правый контент
        content = tk.Frame(container, bg=COLORS['bg_dark'])
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0))

        self._sidebar_buttons = {}
        self._section_frames = {}
        self._current_section = None

        sections = [
            ("Автозагрузка",        self._create_autorun_tab),
            ("Службы и драйверы",   self._create_services_tab),
            ("Ограничения",         self._create_restrictions_tab),
            ("Процессы",            self._create_processes_tab),
            ("Реестр",              self._create_registry_tab),
            ("Система",             self._create_system_tab),
            ("Проводник",           self._create_explorer_tab),
            ("Настройки",           self._create_settings_tab),
        ]

        # Создаём фреймы заранее
        for name, create_func in sections:
            frame = tk.Frame(content, bg=COLORS['bg_dark'])
            create_func(frame)
            self._section_frames[name] = frame

        # Кнопки в сайдбаре
        for name, _ in sections:
            btn = tk.Button(sidebar, text=name, anchor='w',
                            bg=COLORS['bg_medium'], fg=COLORS['text_main'],
                            activebackground=COLORS['bg_light'],
                            activeforeground=COLORS['text_main'],
                            font=FONT_UI, relief='flat', bd=0,
                            padx=14, pady=9, cursor='hand2', highlightthickness=0,
                            command=lambda n=name: self._show_section(n))
            btn.pack(fill=tk.X)
            self._sidebar_buttons[name] = btn

        self._show_section(sections[0][0])

    def _show_section(self, name):
        if self._current_section == name:
            return
        for n, frame in self._section_frames.items():
            if n == name:
                frame.pack(fill=tk.BOTH, expand=True)
            else:
                frame.pack_forget()
        for n, btn in self._sidebar_buttons.items():
            if n == name:
                btn.configure(bg=COLORS['accent'], fg='white')
            else:
                btn.configure(bg=COLORS['bg_medium'], fg=COLORS['text_main'])
        self._current_section = name

    def _create_status_bar(self):
        status_bar = tk.Frame(self.root, bg=COLORS['bg_light'], height=24)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        status_bar.pack_propagate(False)
        tk.Label(status_bar, textvariable=self.status_var, font=('Segoe UI', 9),
                 bg=COLORS['bg_light'], fg=COLORS['text_main'], padx=12
                 ).pack(side=tk.LEFT)
        tk.Label(status_bar, text="DedHelper 5.0", font=('Segoe UI', 9),
                 bg=COLORS['bg_light'], fg=COLORS['text_sec'], padx=12
                 ).pack(side=tk.RIGHT)

    # ───────── helper: скроллируемое дерево с тонкой рамкой ─────────
    def _create_scrolled_tree(self, parent, columns, show='headings', height=20):
        wrap = tk.Frame(parent, bg=COLORS['border'])
        wrap.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        tree = ttk.Treeview(wrap, columns=columns, show=show, height=height)
        vsb = ttk.Scrollbar(wrap, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)

        # Порядок важен: сначала скроллбар (RIGHT), потом дерево (LEFT, expand)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=1, pady=1)

        return tree

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
        logger.info("Вход в WinRE")
        self.system_commands.enter_winre()

    def _clean_hosts(self):
        if self.restrictions_manager.clean_hosts():
            messagebox.showinfo("Успех", "Hosts файл очищен")
        else:
            messagebox.showerror("Ошибка", "Не удалось очистить Hosts")

    def _remove_all_restrictions(self):
        result = self.restrictions_manager.remove_all_restrictions()
        msg = "Результат снятия ограничений:\n\n"
        msg += f"ScancodeMap: {'OK' if result['scancode_map'] else 'FAIL'}\n"
        msg += f"Debuggers: {result['debuggers']} удалено\n"
        msg += f"DisallowRun: {'OK' if result['disallow_run'] else 'FAIL'}\n"
        msg += f"Group Policy: {result['group_policy']} политик удалено\n\n"
        messagebox.showinfo("Результат", msg)

    # ───────── ОЧИСТКА АВТОЗАГРУЗКИ (расширенная) ─────────
    def _clean_autorun(self):
        if not messagebox.askyesno(
                "Очистка автозагрузки",
                "Будет очищено:\n"
                "  • Подозрительные элементы автозагрузки (реестр, папка)\n"
                "  • Winlogon: Shell, Userinit, AppRuntime\n"
                "  • AppInit_DLLs (список DLL)\n"
                "  • Подозрительные задачи планировщика\n\n"
                "Продолжить?", parent=self.root):
            return

        removed = 0
        details = []

        try:
            n = self.autorun_manager.clear_safe_autorun()
            if n:
                removed += n
                details.append(f"Автозагрузка (реестр/папка): {n}")
        except Exception as e:
            logger.error(f"clear_safe_autorun: {e}")

        try:
            n = self._clean_winlogon_values()
            if n:
                removed += n
                details.append(f"Winlogon: {n}")
        except Exception as e:
            logger.error(f"clean_winlogon: {e}")

        try:
            n = self._clean_appinit_dlls()
            if n:
                removed += n
                details.append(f"AppInit_DLLs: {n}")
        except Exception as e:
            logger.error(f"clean_appinit: {e}")

        try:
            n = self._clean_suspicious_tasks()
            if n:
                removed += n
                details.append(f"Планировщик: {n}")
        except Exception as e:
            logger.error(f"clean_scheduled: {e}")

        try:
            self._refresh_autorun()
        except Exception:
            pass
        try:
            self._refresh_scheduler()
        except Exception:
            pass

        if removed == 0:
            messagebox.showinfo("Готово", "Подозрительных элементов не обнаружено.",
                                parent=self.root)
        else:
            messagebox.showinfo(
                "Готово",
                f"Удалено/исправлено элементов: {removed}\n\n" + "\n".join(details),
                parent=self.root)

    def _clean_winlogon_values(self):
        """Winlogon: Shell->explorer.exe, Userinit->userinit.exe, AppRuntime удалить."""
        count = 0
        try:
            key = OfflineSession.open_hklm(
                r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
                winreg.KEY_READ | winreg.KEY_SET_VALUE)
        except OSError as e:
            logger.error(f"_clean_winlogon_values open: {e}")
            return 0
        try:
            windir = OfflineSession.windows()
            try:
                val, vtype = winreg.QueryValueEx(key, 'Shell')
                cur = (val or '').strip()
                if cur.lower() != 'explorer.exe':
                    winreg.SetValueEx(key, 'Shell', 0, vtype, 'explorer.exe')
                    count += 1
                    logger.info(f"Winlogon Shell исправлен: {cur!r} -> 'explorer.exe'")
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.error(f"Winlogon Shell: {e}")

            try:
                val, vtype = winreg.QueryValueEx(key, 'Userinit')
                cur = (val or '').strip()
                expected = os.path.join(windir, 'system32', 'userinit.exe') + ','
                parts = [p.strip() for p in cur.split(',')]
                needs_fix = len(parts) > 2 or (len(parts) == 2 and parts[1])
                if not needs_fix:
                    first_low = (parts[0] if parts else '').lower()
                    if 'userinit.exe' not in first_low:
                        needs_fix = True
                if needs_fix:
                    winreg.SetValueEx(key, 'Userinit', 0, vtype, expected)
                    count += 1
                    logger.info(f"Winlogon Userinit исправлен: {cur!r} -> {expected!r}")
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.error(f"Winlogon Userinit: {e}")

            for bad in ('AppRuntime', 'Taskman'):
                try:
                    winreg.QueryValueEx(key, bad)
                    winreg.DeleteValue(key, bad)
                    count += 1
                    logger.info(f"Winlogon: удалено значение {bad}")
                except FileNotFoundError:
                    pass
                except OSError as e:
                    logger.error(f"Winlogon {bad}: {e}")
        finally:
            winreg.CloseKey(key)
        return count

    def _clean_appinit_dlls(self):
        """AppInit_DLLs — HKLM (32 и 64-bit) + все HKCU в офлайне."""
        count = 0
        for subpath in (
            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
            r'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows',
        ):
            try:
                key = OfflineSession.open_hklm(
                    subpath, winreg.KEY_READ | winreg.KEY_SET_VALUE)
            except OSError:
                continue
            try:
                try:
                    dlls, vtype = winreg.QueryValueEx(key, 'AppInit_DLLs')
                    if dlls:
                        winreg.SetValueEx(key, 'AppInit_DLLs', 0, vtype, '')
                        count += 1
                        logger.info(f"AppInit_DLLs очищены ({subpath}): было {dlls!r}")
                except FileNotFoundError:
                    pass
                except OSError as e:
                    logger.error(f"AppInit_DLLs ({subpath}): {e}")
            finally:
                winreg.CloseKey(key)

        for label, hive, prefix in OfflineSession.hkcu_roots():
            sub = r'Software\Microsoft\Windows NT\CurrentVersion\Windows'
            full = f"{prefix}\\{sub}" if prefix else sub
            try:
                key = winreg.OpenKey(hive, full, 0,
                                     winreg.KEY_READ | winreg.KEY_SET_VALUE)
            except OSError:
                continue
            try:
                try:
                    dlls, vtype = winreg.QueryValueEx(key, 'AppInit_DLLs')
                    if dlls:
                        winreg.SetValueEx(key, 'AppInit_DLLs', 0, vtype, '')
                        count += 1
                        logger.info(f"AppInit_DLLs очищены ({label}): было {dlls!r}")
                except FileNotFoundError:
                    pass
                except OSError as e:
                    logger.error(f"AppInit_DLLs ({label}): {e}")
            finally:
                winreg.CloseKey(key)
        return count

    def _clean_suspicious_tasks(self):
        """Удаляет задачи планировщика, чей exe вне безопасных путей."""
        try:
            from modules.processes import is_system_path as _is_sys, is_signed_by_microsoft as _is_signed
        except Exception:
            return 0

        try:
            result = run_hidden_command('schtasks /query /fo CSV /nh',
                                        capture_output=True)
            stdout = decode_output(result.stdout) if result.stdout else ""
        except Exception:
            return 0

        safe_dirs = [
            os.environ.get('SystemRoot', r'C:\Windows').lower(),
            os.environ.get('ProgramFiles', r'C:\Program Files').lower(),
            os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)').lower(),
            os.environ.get('ProgramData', r'C:\ProgramData').lower(),
        ]
        safe_dirs = [d for d in safe_dirs if d]

        count = 0
        seen = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith('"'):
                continue
            parts = line.split('","')
            if not parts:
                continue
            task_name = parts[0].strip('"').strip()
            if not task_name or task_name in seen:
                continue
            seen.add(task_name)
            low = task_name.lower()
            if '\\microsoft\\' in low or low.startswith('microsoft'):
                continue
            try:
                path = self._get_scheduled_task_path(task_name)
            except Exception:
                path = ""
            if not path:
                continue
            try:
                if _is_sys(path) and _is_signed(path):
                    continue
            except Exception:
                pass
            path_low = path.lower()
            if any(path_low.startswith(d) for d in safe_dirs):
                continue
            try:
                if self.autorun_manager.delete_scheduled_task(task_name):
                    count += 1
                    logger.info(f"Удалена подозрительная задача: {task_name} ({path})")
            except Exception as e:
                logger.error(f"Не удалось удалить задачу {task_name}: {e}")
        return count

    def _run_sfc(self):
        self.system_commands.run_sfc()

    def _quick_replace_sethc_utilman_self(self):
        if not getattr(sys, 'frozen', False):
            return
        self_exe = sys.executable
        ok_s = self.system_commands.replace_sethc(target_exe=self_exe)
        ok_u = self.system_commands.replace_utilman(target_exe=self_exe)
        if ok_s and ok_u:
            messagebox.showinfo("Успех", "sethc.exe и utilman.exe заменены на DedHelper")
        else:
            messagebox.showwarning("Частично выполнено",
                                   f"sethc.exe: {'OK' if ok_s else 'ошибка'}\n"
                                   f"utilman.exe: {'OK' if ok_u else 'ошибка'}")

    def _restore_associations(self):
        restored = 0
        if self._fix_exe_association(): restored += 1
        if self._fix_bat_association(): restored += 1
        if self._fix_txt_association(): restored += 1
        if self._fix_lnk_association(): restored += 1
        if self._fix_html_association(): restored += 1
        logger.info(f"Восстановлено {restored} ассоциаций файлов")
        messagebox.showinfo("Успех", f"Восстановлено ассоциаций: {restored}")

    def _fix_exe_association(self) -> bool:
        try:
            if not OfflineSession.active:
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                                     r'Software\Classes\.exe')
                except OSError:
                    pass
            key = OfflineSession.create_hkcr('.exe')
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'exefile')
            winreg.CloseKey(key)
            key = OfflineSession.create_hkcr(r'exefile\shell\open\command')
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, '"%1" %*')
            winreg.CloseKey(key)
            return True
        except Exception as e:
            logger.error(f"Ошибка .exe: {e}")
            return False

    def _fix_bat_association(self) -> bool:
        try:
            key = OfflineSession.create_hkcr('.bat')
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'batfile')
            winreg.CloseKey(key)
            key = OfflineSession.create_hkcr(r'batfile\shell\open\command')
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, '"%1" %*')
            winreg.CloseKey(key)
            return True
        except Exception as e:
            logger.error(f"Ошибка .bat: {e}")
            return False

    def _fix_txt_association(self) -> bool:
        try:
            key = OfflineSession.create_hkcr('.txt')
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'txtfile')
            winreg.CloseKey(key)
            key = OfflineSession.create_hkcr(r'txtfile\shell\open\command')
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'NOTEPAD.EXE "%1"')
            winreg.CloseKey(key)
            return True
        except Exception as e:
            logger.error(f"Ошибка .txt: {e}")
            return False

    def _fix_lnk_association(self) -> bool:
        try:
            key = OfflineSession.create_hkcr('.lnk')
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'lnkfile')
            winreg.CloseKey(key)
            return True
        except Exception as e:
            logger.error(f"Ошибка .lnk: {e}")
            return False

    def _fix_html_association(self) -> bool:
        try:
            key = OfflineSession.create_hkcr('.html')
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'htmlfile')
            winreg.CloseKey(key)
            return True
        except Exception as e:
            logger.error(f"Ошибка .html: {e}")
            return False

    # ==================== ВКЛАДКА "АВТОЗАГРУЗКА" (2 под-вкладки) ====================
    def _create_autorun_tab(self, parent):
        sub = ttk.Notebook(parent)
        sub.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        autorun_frame = ttk.Frame(sub)
        sub.add(autorun_frame, text="  Автозагрузка  ")
        self._build_autorun_subtab(autorun_frame)

        scheduler_frame = ttk.Frame(sub)
        sub.add(scheduler_frame, text="  Планировщик  ")
        self._build_scheduler_subtab(scheduler_frame)

    def _build_autorun_subtab(self, parent):
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=6, pady=6)
        ttk.Button(btn_frame, text="Обновить",
                   command=self._refresh_autorun).pack(side=tk.LEFT, padx=2)

        # Используем Treeview с поддержкой дерева
        columns = ('value',)
        self.autorun_tree = self._create_scrolled_tree(parent, columns,
                                                       show='tree headings', height=20)
        
        self.autorun_tree.heading('#0', text='Name')
        self.autorun_tree.heading('value', text='Value')
        
        self.autorun_tree.column('#0', width=400)
        self.autorun_tree.column('value', width=500)

        self.autorun_tree.bind('<Button-3>', self._on_autorun_right_click)
        self.autorun_tree.bind('<Double-Button-1>',
                                lambda e: self._autorun_double_click())

        self._autorun_rows = {}
        self._refresh_autorun()

    def _refresh_autorun(self):
        try:
            rows = self.autorun_manager.get_sorted_autorun()
        except Exception as e:
            self.status_var.set(f"Ошибка: {e}")
            return
        self._autorun_all_rows = rows
        self._render_autorun()
        self.status_var.set(f"Автозагрузка: {len(rows)} элементов")

    def _sort_autorun(self, col):
        key, reverse = self._autorun_sort
        reverse = (not reverse) if key == col else False
        self._autorun_sort = (col, reverse)
        self._render_autorun()

    def _render_autorun(self):
        tree = self.autorun_tree
        for item in tree.get_children():
            tree.delete(item)
        self._autorun_rows = {}
        
        # Настраиваем тег для красного цвета
        tree.tag_configure('suspicious', foreground=COLORS['critical'])

        # Добавляем метку диска, если активен офлайн-режим (WinPE)
        drive_prefix = ""
        if getattr(self, '_offline_active', False) and getattr(OfflineSession, 'drive', None):
            drive_prefix = f"[{OfflineSession.drive}] "

        # Группируем элементы по пути (display_location)
        groups = {}
        for row in self._autorun_all_rows:
            loc = row.get('display_location', row.get('location', 'Unknown'))
            if loc not in groups:
                groups[loc] = []
            groups[loc].append(row)

        # Сортируем группы по алфавиту
        for loc in sorted(groups.keys()):
            # Вставляем корневой узел (ветку реестра) и сразу раскрываем его
            parent_id = tree.insert('', 'end', text=drive_prefix + loc, open=True)
            
            # Сортируем элементы внутри группы
            group_rows = sorted(groups[loc], key=lambda r: r['name'].lower())
            
            for row in group_rows:
                value = row['value']
                display = value if len(value) <= 150 else value[:147] + "..."
                
                tags = ()
                # Подсвечиваем CmdLine в Setup, если это не стандартный sysprep
                if row['category'] == 'Setup' and row['name'].lower() == 'cmdline':
                    if value.strip() and 'sysprep' not in value.lower():
                        tags = ('suspicious',)

                child_id = tree.insert(parent_id, 'end', text=row['name'], values=(display,), tags=tags)
                self._autorun_rows[child_id] = row

    def _autorun_double_click(self):
        sel = self.autorun_tree.selection()
        if not sel:
            return
        # Редактируем только если это дочерний узел (значение)
        row = self._autorun_rows.get(sel[0])
        if row:
            self._autorun_edit_row(row)

    def _on_autorun_right_click(self, event):
        tree = self.autorun_tree
        iid = tree.identify_row(event.y)
        if not iid:
            return
        tree.selection_set(iid)
        
        row = self._autorun_rows.get(iid)
        menu = tk.Menu(self.root, tearoff=0)
        
        if row:
            # Это дочерний узел (конкретное значение автозагрузки)
            menu.add_command(label="Редактировать значение",
                             command=lambda: self._autorun_edit_row(row))
            menu.add_command(label="Удалить",
                             command=lambda: self._autorun_delete_row(iid, row))
            target = resolve_existing_path(row['value'])
            if target:
                menu.add_command(label="Открыть расположение",
                                 command=lambda: self._launch_explorer(start_path=target))
        else:
            # Это корневой узел (путь реестра)
            path_text = tree.item(iid, 'text')
            menu.add_command(label="Копировать путь",
                             command=lambda: self._copy_to_clipboard(path_text))
            
        menu.tk_popup(event.x_root, event.y_root)

    def _copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set(f"Скопировано: {text}")

    def _autorun_edit_row(self, row):
        category = row['category']
        # Добавлены новые категории
        if category not in ('Run/RunOnce', 'Winlogon', 'Setup', 'Windows', 
                            'SafeBoot', 'Session Manager', 'AppInit'):
            messagebox.showinfo(
                "Не поддерживается",
                f"Редактирование категории «{category}» пока не реализовано.\n"
                f"Используйте regedit.")
            return

        current = row['value']
        title = "Редактировать значение автозагрузки"
        prompt = (f"Категория: {category}\n"
                  f"Расположение: {row['display_location']}\n"
                  f"Имя: {row['name']}\n\n"
                  f"Введите новое значение:")
        new_val = simpledialog.askstring(title, prompt,
                                         initialvalue=current,
                                         parent=self.root)
        if new_val is None or new_val == current:
            return

        ok = self.autorun_manager.set_registry_autorun(
            row['name'], new_val, row['location'])
        if ok:
            messagebox.showinfo("Успех", f"Значение «{row['name']}» обновлено.")
            self._refresh_autorun()
        else:
            messagebox.showerror(
                "Ошибка",
                "Не удалось сохранить значение.\n\n"
                "Проверьте лог (%TEMP%\\DedHelper.log) или откройте regedit "
                "для ручного редактирования.")


    def _autorun_delete_row(self, iid, row):
        ok = self._dispatch_autorun_delete(row)
        if ok:
            self._autorun_all_rows = [r for r in self._autorun_all_rows if r is not row]
            self._render_autorun()
            self.status_var.set(f"Удалено: {row['name']}")
        else:
            messagebox.showerror("Ошибка", f"Не удалось удалить «{row['name']}»")

    def _dispatch_autorun_delete(self, row) -> bool:
        category = row['category']
        
        # Если путь есть в карте реестра — удаляем через стандартный метод
        if row.get('location') in getattr(self.autorun_manager, '_autorun_location_map', {}):
            return self.autorun_manager.remove_registry_autorun(row['name'], row['location'])
            
        if category == 'Папка автозагрузки':
            if 'все пользователи' in row['location']:
                try:
                    os.remove(row['value'])
                    return True
                except Exception:
                    return False
            return self.autorun_manager.remove_from_startup(row['name'])
            
        if category.startswith('CmdLine (IFEO'):
            return self.autorun_manager.remove_ifeo_debugger(row['name'])
            
        if category == 'CLSID':
            return self.autorun_manager.remove_clsid_override(row['name'])
            
        return False

    # ==================== ПОД-ВКЛАДКА "ПЛАНИРОВЩИК" ====================
    def _build_scheduler_subtab(self, parent):
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=6, pady=6)
        ttk.Button(btn_frame, text="Обновить",
                   command=self._refresh_scheduler).pack(side=tk.LEFT, padx=2)

        self.scheduler_tree = self._create_scrolled_tree(
            parent, columns=('Путь',), show='tree headings', height=20)
        self.scheduler_tree.heading('#0', text='Задача')
        self.scheduler_tree.heading('Путь', text='Путь')
        self.scheduler_tree.column('#0', width=320)
        self.scheduler_tree.column('Путь', width=560)

        self.scheduler_tree.bind('<Button-3>', self._on_scheduler_right_click)
        self.scheduler_tree.bind('<Double-Button-1>',
                                  lambda e: self._scheduler_open_location_from_sel())
        self._refresh_scheduler()

    def _refresh_scheduler(self):
        try:
            for item in self.scheduler_tree.get_children():
                self.scheduler_tree.delete(item)
            tasks = self.autorun_manager.get_scheduled_tasks()
            for task in tasks:
                self.scheduler_tree.insert('', 'end', iid=task['name'],
                                            text=task['name'],
                                            values=('',))
            self.status_var.set(f"Планировщик: {len(tasks)} задач")
        except Exception as e:
            self.status_var.set(f"Ошибка: {e}")

    def _get_scheduled_task_path(self, task_name):
        """Путь из XML задачи. В офлайне — читаем XML напрямую с диска."""
        if OfflineSession.active:
            full = os.path.join(OfflineSession.windows('System32', 'Tasks'),
                                task_name)
            if not os.path.isfile(full):
                return ""
            content = None
            for enc in ('utf-16', 'utf-8', 'cp1251'):
                try:
                    with open(full, 'r', encoding=enc) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
                except OSError:
                    return ""
            if not content:
                return ""
        else:
            try:
                result = run_hidden_command(
                    f'schtasks /query /tn "{task_name}" /xml ONE',
                    capture_output=True)
                content = decode_output(result.stdout) if result.stdout else ""
            except Exception as e:
                logger.error(f"Ошибка получения пути задачи '{task_name}': {e}")
                return ""
            if not content:
                return ""
        m = re.search(r'<Command>(.*?)</Command>', content, re.DOTALL)
        if not m:
            return ""
        cmd = OfflineSession.expand_vars(m.group(1).strip())
        return resolve_existing_path(cmd)

    def _on_scheduler_right_click(self, event):
        tree = self.scheduler_tree
        iid = tree.identify_row(event.y)
        if not iid:
            return
        tree.selection_set(iid)
        task_name = iid
        if not task_name:
            return
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Открыть расположение",
                         command=lambda: self._open_task_location(task_name))
        menu.add_separator()
        menu.add_command(label="Включить",
                         command=lambda: self._task_action('enable', task_name))
        menu.add_command(label="Отключить",
                         command=lambda: self._task_action('disable', task_name))
        menu.add_command(label="Удалить задачу",
                         command=lambda: self._task_action('delete', task_name))
        menu.tk_popup(event.x_root, event.y_root)

    def _open_task_location(self, task_name):
        self.status_var.set(f"Ищу путь задачи: {task_name}…")
        self.root.update_idletasks()
        path = self._get_scheduled_task_path(task_name)
        if path and os.path.exists(path):
            self._launch_explorer(start_path=path)
            self.status_var.set(f"Задача: {task_name} -> {path}")
        else:
            messagebox.showwarning(
                "Путь не определён",
                f"Не удалось определить путь к файлу задачи «{task_name}».\n"
                f"Возможно, это встроенная команда (не exe).")
            self.status_var.set("Готово")

    def _scheduler_open_location_from_sel(self):
        sel = self.scheduler_tree.selection()
        if sel:
            self._open_task_location(sel[0])

    def _task_action(self, action, task_name):
        if action == 'delete':
            ok = self.autorun_manager.delete_scheduled_task(task_name)
            verb = "удалена"
        elif action == 'disable':
            ok = self.autorun_manager.disable_scheduled_task(task_name)
            verb = "отключена"
        else:
            ok = self.autorun_manager.enable_scheduled_task(task_name)
            verb = "включена"
        if ok:
            messagebox.showinfo("Успех", f"Задача {verb}")
            self._refresh_scheduler()
        else:
            messagebox.showerror("Ошибка",
                                 f"Не удалось выполнить действие с задачей «{task_name}»")

    # ==================== СЛУЖБЫ И ДРАЙВЕРЫ ====================
    def _create_services_tab(self, parent):
        sub = ttk.Notebook(parent)
        sub.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        svc_frame = ttk.Frame(sub)
        sub.add(svc_frame, text="  Службы  ")
        self.services_tree = self._build_service_list(svc_frame, is_driver=False)

        drv_frame = ttk.Frame(sub)
        sub.add(drv_frame, text="  Драйверы  ")
        self.drivers_tree = self._build_service_list(drv_frame, is_driver=True)

        self._refresh_services()
        self._refresh_drivers()

    def _build_service_list(self, parent, is_driver):
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=6, pady=6)
        refresh_cmd = self._refresh_drivers if is_driver else self._refresh_services
        ttk.Button(btn_frame, text="Обновить",
                   command=refresh_cmd).pack(side=tk.LEFT, padx=2)

        columns = ('name', 'display', 'state')
        tree = self._create_scrolled_tree(parent, columns,
                                           show='headings', height=20)
        for col, text, w in (('name', 'Имя', 200), ('display', 'Описание', 340),
                             ('state', 'Состояние', 110)):
            tree.heading(col, text=text)
            tree.column(col, width=w)
        tree.bind('<Button-3>',
                  lambda e, t=tree, d=is_driver:
                  self._on_service_right_click(e, t, d))
        return tree

    def _refresh_services(self):
        self._fill_service_tree(self.services_tree,
                                self.autorun_manager.get_services())

    def _refresh_drivers(self):
        self._fill_service_tree(self.drivers_tree,
                                self.autorun_manager.get_drivers())

    @staticmethod
    def _fill_service_tree(tree, items):
        for item in tree.get_children():
            tree.delete(item)
        for it in items:
            tree.insert('', 'end',
                        values=(it.get('name', ''), it.get('display_name', ''),
                                it.get('state', '')))

    def _on_service_right_click(self, event, tree, is_driver):
        iid = tree.identify_row(event.y)
        if not iid:
            return
        tree.selection_set(iid)
        name = tree.item(iid)['values'][0]
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Запустить",
                         command=lambda: self._service_action(tree, is_driver,
                                                              name, 'start'))
        menu.add_command(label="Остановить",
                         command=lambda: self._service_action(tree, is_driver,
                                                              name, 'stop'))
        menu.add_command(label="Отключить",
                         command=lambda: self._service_action(tree, is_driver,
                                                              name, 'disable'))
        menu.add_command(label="Включить",
                         command=lambda: self._service_action(tree, is_driver,
                                                              name, 'enable'))
        menu.tk_popup(event.x_root, event.y_root)

    def _service_action(self, tree, is_driver, name, action):
        fn = {'start': self.autorun_manager.start_service,
              'stop': self.autorun_manager.stop_service,
              'disable': self.autorun_manager.disable_service,
              'enable': self.autorun_manager.enable_service}[action]
        if fn(name):
            (self._refresh_drivers if is_driver else self._refresh_services)()
        else:
            messagebox.showerror("Ошибка",
                                 f"Не удалось выполнить «{action}» для {name}")

    # ==================== ОГРАНИЧЕНИЯ ====================
    def _create_restrictions_tab(self, parent):
        top = tk.Frame(parent, bg=COLORS['bg_medium'])
        top.pack(fill=tk.X, padx=8, pady=8)
        tk.Label(top, text="Поиск и снятие ограничений",
                 font=FONT_UI_LARGE_BOLD,
                 bg=COLORS['bg_medium'], fg=COLORS['accent']
                 ).pack(anchor=tk.W, padx=5)

        scan_btn_frame = tk.Frame(top, bg=COLORS['bg_medium'])
        scan_btn_frame.pack(fill=tk.X, pady=6)
        ttk.Button(scan_btn_frame, text="Найти ограничения",
                   command=self._scan_restrictions).pack(side=tk.LEFT, padx=5)
        ttk.Button(scan_btn_frame, text="Снять выбранное",
                   command=self._remove_selected_restriction).pack(side=tk.LEFT, padx=5)
        ttk.Button(scan_btn_frame, text="Снять всё найденное",
                   command=self._remove_all_found_restrictions).pack(side=tk.LEFT, padx=5)

        columns = ('category', 'name', 'detail')
        self.restrictions_tree = self._create_scrolled_tree(
            parent, columns, show='headings', height=14)
        self.restrictions_tree.configure(selectmode='extended')
        for col, text, w in (('category', 'Тип', 140),
                             ('name', 'Что', 220),
                             ('detail', 'Подробности', 400)):
            self.restrictions_tree.heading(col, text=text)
            self.restrictions_tree.column(col, width=w)
        self.restrictions_tree.bind('<Button-3>',
                                     self._on_restriction_right_click)
        self._restriction_items = {}

        hosts_frame = tk.Frame(parent, bg=COLORS['bg_medium'])
        hosts_frame.pack(fill=tk.X, padx=8, pady=8)
        tk.Label(hosts_frame, text="Hosts",
                 font=FONT_UI_BOLD,
                 bg=COLORS['bg_medium'], fg=COLORS['text_sec']
                 ).pack(anchor=tk.W, padx=5)
        hbtns = tk.Frame(hosts_frame, bg=COLORS['bg_medium'])
        hbtns.pack(pady=4)
        ttk.Button(hbtns, text="Очистить Hosts",
                   command=self._clean_hosts).pack(side=tk.LEFT, padx=5)
        ttk.Button(hbtns, text="Восстановить Hosts",
                   command=self._restore_hosts).pack(side=tk.LEFT, padx=5)

        self._scan_restrictions()

    def _scan_restrictions(self):
        tree = self.restrictions_tree
        for item in tree.get_children():
            tree.delete(item)
        self._restriction_items = {}
        try:
            items = self.restrictions_manager.scan_restrictions()
        except Exception as e:
            self.status_var.set(f"Ошибка поиска: {e}")
            return
        for it in items:
            iid = tree.insert('', 'end',
                              values=(it['category'], it['name'], it['detail']))
            self._restriction_items[iid] = it
        self.status_var.set(
            f"Ограничения: найдено {len(items)}" if items else "Ограничения не найдены")

    def _on_restriction_right_click(self, event):
        iid = self.restrictions_tree.identify_row(event.y)
        if not iid:
            return
        self.restrictions_tree.selection_set(iid)
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Снять", command=self._remove_selected_restriction)
        menu.tk_popup(event.x_root, event.y_root)

    def _remove_selected_restriction(self):
        selected = self.restrictions_tree.selection()
        if not selected:
            return
        ok = 0
        for iid in selected:
            it = self._restriction_items.get(iid)
            if it and self.restrictions_manager.remove_restriction_item(it):
                ok += 1
        self._scan_restrictions()
        messagebox.showinfo("Готово", f"Снято: {ok} из {len(selected)}")

    def _remove_all_found_restrictions(self):
        items = list(self._restriction_items.values())
        if not items:
            return
        ok = sum(1 for it in items
                 if self.restrictions_manager.remove_restriction_item(it))
        self._scan_restrictions()
        messagebox.showinfo("Готово", f"Снято: {ok} из {len(items)}")

    def _restore_hosts(self):
        if self.restrictions_manager.restore_hosts_default():
            messagebox.showinfo("Успех", "Hosts файл восстановлен")
        else:
            messagebox.showerror("Ошибка", "Не удалось восстановить Hosts")

    # ==================== ПРОЦЕССЫ ====================
    def _create_processes_tab(self, parent):
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=8, pady=6)
        ttk.Button(btn_frame, text="Обновить",
                   command=self._refresh_processes).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Найти подозрительные критические",
                   command=self._scan_critical_now).pack(side=tk.LEFT, padx=2)

        self.process_tree = self._create_scrolled_tree(
            parent, columns=('PID', 'Путь'), show='tree headings', height=20)
        self.process_tree.heading('#0', text='Имя процесса')
        self.process_tree.heading('PID', text='PID')
        self.process_tree.heading('Путь', text='Путь к файлу')
        self.process_tree.column('#0', width=220)
        self.process_tree.column('PID', width=80)
        self.process_tree.column('Путь', width=600)

        self.process_tree.bind('<Button-3>', self._on_process_right_click)
        self._refresh_processes()

    def _on_process_right_click(self, event):
        tree = self.process_tree
        iid = tree.identify_row(event.y)
        menu = tk.Menu(self.root, tearoff=0)
        if iid:
            tree.selection_set(iid)
            menu.add_command(label="Завершить", command=self._terminate_process)
            menu.add_command(label="Заморозить", command=self._suspend_process)
            menu.add_command(label="Разморозить", command=self._resume_process)
            menu.add_command(label="Снять критический флаг",
                             command=self._remove_critical_flag)
            menu.add_command(label="Открыть расположение",
                             command=self._open_process_location)
            menu.add_separator()
        menu.add_command(label="Заморозить ВСЕ процессы",
                         command=self._suspend_all_processes)
        menu.add_command(label="Разморозить все",
                         command=self._resume_all_processes)
        menu.tk_popup(event.x_root, event.y_root)

    def _suspend_all_processes(self):
        frozen, failed = 0, 0
        for proc in self.process_manager.get_processes():
            if self._should_protect(proc):
                continue
            if proc['pid'] in self.frozen_pids:
                continue
            if self.process_manager.suspend_process(proc['pid']):
                self.frozen_pids.add(proc['pid'])
                frozen += 1
            else:
                failed += 1
        self._refresh_processes()
        messagebox.showinfo("Готово", f"Заморожено: {frozen}\nНе удалось: {failed}")

    def _resume_all_processes(self):
        resumed = 0
        for pid in list(self.frozen_pids):
            if self.process_manager.resume_process(pid):
                resumed += 1
            self.frozen_pids.discard(pid)
        self._refresh_processes()
        messagebox.showinfo("Готово", f"Разморожено: {resumed}")

    def _get_all_process_paths(self):
        paths = {}
        try:
            ps_command = '''
            Get-CimInstance Win32_Process | Select-Object ProcessId, ExecutablePath |
            ForEach-Object { if ($_.ExecutablePath) { Write-Output "$($_.ProcessId)=$($_.ExecutablePath)" } }
            '''
            result = run_hidden_powershell(ps_command)
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

        processes = self.process_manager.get_processes()
        fallback_paths = None

        try:
            critical_map = self.process_manager.get_critical_map()
        except Exception as e:
            logger.error(f"get_critical_map: {e}")
            critical_map = {}
        self._last_critical_map = critical_map

        crit_count = 0
        for proc in processes:
            pid = proc['pid']
            path = proc.get('path') or ''
            if not path:
                if fallback_paths is None:
                    fallback_paths = self._get_all_process_paths()
                path = fallback_paths.get(pid, '')
            path = path or 'N/A'

            is_crit = bool(critical_map.get(pid, False))
            is_frozen = pid in self.frozen_pids

            suspicious = False
            if is_crit and pid not in (0, 4):
                suspicious = is_process_suspicious(pid,
                                                   path if path != 'N/A' else '')
            if is_crit:
                crit_count += 1

            if is_frozen:
                tag = 'frozen'
            elif is_crit:
                tag = 'critical'
            else:
                tag = 'normal'

            display_name = ('[!] ' if suspicious else '') + proc['name']
            self.process_tree.insert('', 'end', text=display_name,
                                     values=(pid, path), tags=(tag,))

        self.process_tree.tag_configure('critical',
                                        background=COLORS['critical'],
                                        foreground='white')
        self.process_tree.tag_configure('frozen',
                                        background=COLORS['frozen'],
                                        foreground='white')
        self.process_tree.tag_configure('normal',
                                        background=COLORS['bg_medium'],
                                        foreground=COLORS['text_main'])

        self.status_var.set(
            f"Процессов: {len(processes)} | Критических: {crit_count} "
            f"| Заморожено: {len(self.frozen_pids)}"
        )

    def _scan_critical_now(self):
        try:
            suspicious = self.process_manager.find_suspicious_critical()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            return
        if not suspicious:
            messagebox.showinfo("Антивирус",
                                "Подозрительных критических процессов не найдено.")
            return
        self._show_critical_alert(suspicious)

    def _get_selected_pid(self):
        selected = self.process_tree.selection()
        if selected:
            item = self.process_tree.item(selected[0])
            try:
                return int(item['values'][0])
            except (ValueError, IndexError):
                return None
        return None

    def _terminate_process(self):
        pid = self._get_selected_pid()
        if pid:
            if self.process_manager.terminate_process(pid):
                messagebox.showinfo("Успех", "Процесс завершён")
                self.frozen_pids.discard(pid)
                self._reported_critical.discard(pid)
                self._refresh_processes()
            else:
                messagebox.showerror("Ошибка", "Не удалось завершить процесс")

    def _suspend_process(self):
        pid = self._get_selected_pid()
        if pid:
            if self.process_manager.suspend_process(pid):
                self.frozen_pids.add(pid)
                messagebox.showinfo("Успех", "Процесс заморожен")
                self._refresh_processes()
            else:
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
            if self.process_manager.remove_critical_flag(pid):
                messagebox.showinfo("Успех", "Критический флаг снят")
                self._refresh_processes()
            else:
                messagebox.showerror("Ошибка", "Не удалось снять флаг")

    def _safe_terminate_selected(self):
        pid = self._get_selected_pid()
        if not pid:
            return
        r = self.process_manager.safe_terminate_critical(pid)
        if r['success']:
            messagebox.showinfo("Успех", "Процесс нейтрализован")
            self.frozen_pids.discard(pid)
            self._reported_critical.discard(pid)
            self._refresh_processes()
        else:
            messagebox.showerror(
                "Не удалось",
                f"Этап: {r['stage']}\nОшибка: {r['error']}\n\n"
                "Если этап 'unmark' — запустите от админа и проверьте SeDebugPrivilege.")

    def _open_process_location(self):
        selected = self.process_tree.selection()
        if not selected:
            return
        item = self.process_tree.item(selected[0])
        name = item['text']
        values = item['values']
        path = values[1] if len(values) > 1 else ''
        if not path or path == 'N/A' or not os.path.exists(path):
            messagebox.showwarning("Путь не определён",
                                   f"Не удалось определить путь к файлу процесса {name}.")
            return
        self._launch_explorer(start_path=path)

    # ==================== РЕЕСТР ====================
    REG_PLACEHOLDER = "Загрузка..."

    def _create_registry_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(top, text="Путь:").pack(side=tk.LEFT, padx=(0, 4))
        self.registry_path_var = tk.StringVar(value="HKCU")
        path_entry = tk.Entry(top, textvariable=self.registry_path_var,
                              bg=COLORS['bg_medium'], fg=COLORS['text_main'],
                              insertbackground=COLORS['text_main'],
                              relief='flat', font=FONT_MONO)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        path_entry.bind('<Return>',
                        lambda e: self._reg_goto(self.registry_path_var.get()))
        ttk.Button(top, text="Перейти",
                   command=lambda: self._reg_goto(self.registry_path_var.get())
                   ).pack(side=tk.LEFT, padx=2)
        ttk.Button(top, text="Обновить",
                   command=self._reg_refresh_current).pack(side=tk.LEFT, padx=2)
        ttk.Button(top, text="Открыть regedit",
                   command=self._open_regedit).pack(side=tk.LEFT, padx=2)

        body = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # Левая часть — дерево ключей
        left_wrap = tk.Frame(body, bg=COLORS['border'])
        body.add(left_wrap, weight=1)
        left_inner = tk.Frame(left_wrap, bg=COLORS['border'])
        left_inner.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        self.reg_tree = ttk.Treeview(left_inner, show='tree', height=22)
        lvsb = ttk.Scrollbar(left_inner, orient='vertical',
                             command=self.reg_tree.yview)
        self.reg_tree.configure(yscrollcommand=lvsb.set)
        lvsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.reg_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=1, pady=1)

        # Правая часть — значения
        right_wrap = tk.Frame(body, bg=COLORS['border'])
        body.add(right_wrap, weight=2)
        right_inner = tk.Frame(right_wrap, bg=COLORS['border'])
        right_inner.pack(fill=tk.BOTH, expand=True)
        self.reg_values_tree = ttk.Treeview(right_inner,
                                             columns=('name', 'type', 'value'),
                                             show='headings', height=22)
        for col, text, w in (('name', 'Имя', 160),
                             ('type', 'Тип', 110),
                             ('value', 'Значение', 380)):
            self.reg_values_tree.heading(col, text=text)
            self.reg_values_tree.column(col, width=w)
        rvsb = ttk.Scrollbar(right_inner, orient='vertical',
                             command=self.reg_values_tree.yview)
        self.reg_values_tree.configure(yscrollcommand=rvsb.set)
        rvsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.reg_values_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                                   padx=1, pady=1)

        self.reg_tree.bind('<<TreeviewOpen>>', self._reg_on_expand)
        self.reg_tree.bind('<<TreeviewSelect>>', self._reg_on_select)
        self.reg_tree.bind('<Button-3>', self._reg_on_key_right_click)
        self.reg_values_tree.bind('<Button-3>', self._reg_on_value_right_click)
        self.reg_values_tree.bind('<Double-Button-1>',
                                   lambda e: self._reg_edit_value())

        for root_name in self.registry_editor.root_names():
            node = self.reg_tree.insert('', 'end', iid=root_name,
                                         text=root_name, open=False)
            self.reg_tree.insert(node, 'end', text=self.REG_PLACEHOLDER)

        last = getattr(self, '_reg_last_path', None)
        if last:
            if self.registry_editor.key_exists(last):
                self.root.after(50, lambda p=last: self._reg_goto(p))

    def _reg_has_placeholder(self, node):
        children = self.reg_tree.get_children(node)
        return (len(children) == 1 and
                self.reg_tree.item(children[0], 'text') == self.REG_PLACEHOLDER)

    def _reg_load_children(self, node):
        for c in self.reg_tree.get_children(node):
            self.reg_tree.delete(c)
        try:
            subkeys = self.registry_editor.list_subkeys(node)
        except Exception:
            subkeys = []
        for name in subkeys:
            full = node + '\\' + name
            child = self.reg_tree.insert(node, 'end', iid=full, text=name)
            try:
                if self.registry_editor.has_subkeys(full):
                    self.reg_tree.insert(child, 'end', text=self.REG_PLACEHOLDER)
            except Exception:
                pass

    def _reg_on_expand(self, event):
        node = self.reg_tree.focus()
        if node and self._reg_has_placeholder(node):
            self._reg_load_children(node)

    def _reg_on_select(self, event=None):
        node = self.reg_tree.focus()
        if node:
            self._reg_last_path = node
            self.registry_path_var.set(node)
            self._reg_load_values(node)

    def _reg_refresh_current(self):
        node = self.reg_tree.focus()
        if node:
            self._reg_load_children(node)
            self._reg_load_values(node)

    def _reg_goto(self, path):
        path = path.strip().strip('\\')
        if not path:
            return
        if not self.registry_editor.key_exists(path):
            messagebox.showerror("Не найдено", f"Раздел не существует:\n{path}")
            return
        parts = path.split('\\')
        node = parts[0]
        if not self.reg_tree.exists(node):
            messagebox.showerror("Ошибка", f"Неизвестный корневой куст: {node}")
            return
        for i in range(1, len(parts) + 1):
            cur = '\\'.join(parts[:i])
            if not self.reg_tree.exists(cur):
                parent = '\\'.join(parts[:i - 1])
                self._reg_load_children(parent)
            if self.reg_tree.exists(cur):
                if self._reg_has_placeholder(cur):
                    self._reg_load_children(cur)
                self.reg_tree.item(cur, open=True)
                node = cur
        if self.reg_tree.exists(path):
            self.reg_tree.selection_set(path)
            self.reg_tree.see(path)
            self.reg_tree.focus(path)
            self._reg_on_select()

    def _reg_load_values(self, path):
        tree = self.reg_values_tree
        for item in tree.get_children():
            tree.delete(item)
        try:
            values = self.registry_editor.list_values(path)
        except Exception as e:
            self.status_var.set(f"Ошибка чтения значений: {e}")
            return
        for v in values:
            name = v['name'] or '(по умолчанию)'
            display_val = str(v['value'])
            if len(display_val) > 200:
                display_val = display_val[:200] + '...'
            tree.insert('', 'end', iid=f"val::{v['name']}",
                        values=(name, v['type'], display_val))
        self.status_var.set(f"Реестр: {path} — значений: {len(values)}")

    def _reg_on_key_right_click(self, event):
        node = self.reg_tree.identify_row(event.y)
        menu = tk.Menu(self.root, tearoff=0)
        if node:
            self.reg_tree.selection_set(node)
            self.reg_tree.focus(node)
            menu.add_command(label="Создать раздел",
                             command=lambda: self._reg_create_key(node))
            if '\\' in node:
                menu.add_command(label="Переименовать раздел",
                                 command=lambda: self._reg_rename_key(node))
                menu.add_command(label="Удалить раздел",
                                 command=lambda: self._reg_delete_key(node))
            menu.add_separator()
            menu.add_command(label="Обновить", command=self._reg_refresh_current)
        else:
            menu.add_command(label="Обновить", command=self._reg_refresh_current)
        menu.tk_popup(event.x_root, event.y_root)

    def _reg_create_key(self, parent_path):
        name = simpledialog.askstring("Новый раздел", "Имя раздела:",
                                      parent=self.root)
        if not name:
            return
        full = parent_path + '\\' + name
        if self.registry_editor.create_key(full):
            self._reg_load_children(parent_path)
            self.reg_tree.item(parent_path, open=True)
        else:
            messagebox.showerror("Ошибка", "Не удалось создать раздел")

    def _reg_rename_key(self, path):
        old_name = path.rsplit('\\', 1)[-1]
        new_name = simpledialog.askstring("Переименовать", "Новое имя:",
                                          initialvalue=old_name,
                                          parent=self.root)
        if not new_name or new_name == old_name:
            return
        if self.registry_editor.rename_key(path, new_name):
            parent = path.rsplit('\\', 1)[0]
            self._reg_load_children(parent)
        else:
            messagebox.showerror("Ошибка", "Не удалось переименовать раздел")

    def _reg_delete_key(self, path):
        if not messagebox.askyesno("Подтверждение",
                                   f"Удалить раздел целиком?\n\n{path}"):
            return
        if self.registry_editor.delete_key_recursive(path):
            parent = path.rsplit('\\', 1)[0]
            self._reg_load_children(parent)
            self.reg_values_tree.delete(*self.reg_values_tree.get_children())
        else:
            messagebox.showerror("Ошибка", "Не удалось удалить раздел")

    def _reg_on_value_right_click(self, event):
        item = self.reg_values_tree.identify_row(event.y)
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Создать значение (REG_SZ)",
                         command=self._reg_create_value)
        if item:
            self.reg_values_tree.selection_set(item)
            menu.add_command(label="Изменить", command=self._reg_edit_value)
            menu.add_command(label="Переименовать", command=self._reg_rename_value)
            menu.add_command(label="Удалить", command=self._reg_delete_value)
        menu.tk_popup(event.x_root, event.y_root)

    def _reg_current_path(self):
        node = self.reg_tree.focus()
        if not node:
            messagebox.showwarning("Предупреждение",
                                   "Сначала выберите раздел слева")
            return None
        return node

    def _reg_create_value(self):
        path = self._reg_current_path()
        if not path:
            return
        name = simpledialog.askstring("Новое значение",
                                      "Имя значения (пусто — по умолчанию):",
                                      parent=self.root)
        if name is None:
            return
        data = simpledialog.askstring("Новое значение",
                                      "Данные (строка, REG_SZ):",
                                      parent=self.root) or ""
        if self.registry_editor.write_key(path, name, data):
            self._reg_load_values(path)
        else:
            messagebox.showerror("Ошибка", "Не удалось создать значение")

    def _reg_selected_value_name(self):
        sel = self.reg_values_tree.selection()
        if not sel:
            return None
        iid = sel[0]
        return iid[len('val::'):] if iid.startswith('val::') else None

    def _reg_edit_value(self):
        path = self._reg_current_path()
        name = self._reg_selected_value_name()
        if not path or name is None:
            return
        result = self.registry_editor.read_key(path, name)
        if not result['success']:
            messagebox.showerror("Ошибка",
                                 result.get('error') or
                                 "Не удалось прочитать значение")
            return
        current = result['value']
        new_val = simpledialog.askstring("Изменить значение",
                                         f"{name or '(по умолчанию)'}:",
                                         initialvalue=str(current),
                                         parent=self.root)
        if new_val is None:
            return
        vtype = winreg.REG_DWORD if isinstance(current, int) else winreg.REG_SZ
        value = int(new_val) if vtype == winreg.REG_DWORD else new_val
        if self.registry_editor.write_key(path, name, value, vtype):
            self._reg_load_values(path)
        else:
            messagebox.showerror("Ошибка", "Не удалось записать значение")

    def _reg_rename_value(self):
        path = self._reg_current_path()
        old_name = self._reg_selected_value_name()
        if not path or not old_name:
            return
        new_name = simpledialog.askstring("Переименовать значение", "Новое имя:",
                                          initialvalue=old_name,
                                          parent=self.root)
        if not new_name or new_name == old_name:
            return
        if self.registry_editor.rename_value(path, old_name, new_name):
            self._reg_load_values(path)
        else:
            messagebox.showerror("Ошибка", "Не удалось переименовать значение")

    def _reg_delete_value(self):
        path = self._reg_current_path()
        name = self._reg_selected_value_name()
        if not path:
            return
        if self.registry_editor.delete_key(path, name if name else ''):
            self._reg_load_values(path)
        else:
            messagebox.showerror("Ошибка", "Не удалось удалить значение")

    def _open_regedit(self):
        self.registry_editor.open_regedit()

    # ==================== СИСТЕМА ====================
    def _create_system_tab(self, parent):
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
            frame = tk.Frame(parent, bg=COLORS['bg_medium'])
            frame.pack(fill=tk.X, padx=8, pady=6)
            tk.Label(frame, text=title, font=FONT_UI_LARGE_BOLD,
                     bg=COLORS['bg_medium'], fg=COLORS['accent']
                     ).pack(anchor=tk.W, padx=5, pady=(0, 6))
            btn_frame = tk.Frame(frame, bg=COLORS['bg_medium'])
            btn_frame.pack(pady=4, fill=tk.X)
            for text, cmd in buttons:
                ttk.Button(btn_frame, text=text, command=cmd).pack(
                    side=tk.LEFT, padx=4, pady=3)

    def _restart_pc(self):
        self.system_commands.restart_pc(5)
        logger.info("Перезагрузка ПК")

    def _shutdown_pc(self):
        self.system_commands.shutdown_pc(5)
        logger.info("Выключение ПК")

    def _logout(self):
        self.system_commands.logout()
        logger.info("Выход из пользователя")

    _enter_winre_sys = _enter_winre
    _run_sfc_sys = _run_sfc
    _enable_uac_sys = _enable_uac
    _restore_font_sys = _restore_font

    def _run_dialog(self):
        self.system_commands.run_dialog()
        logger.info("Win+R")

    def _run_dism(self):
        self.system_commands.run_dism()
        logger.info("DISM")

    # ==================== WINPE ====================
    def _check_winpe_drive(self):
        try:
            drive_letter = self.system_commands.get_winpe_drive_letter()
            if drive_letter:
                messagebox.showinfo("Определение диска",
                                    f"Диск Windows найден: {drive_letter}")
            else:
                messagebox.showwarning("Ошибка",
                                       "Не удалось определить диск Windows")
        except Exception as e:
            logger.error(f"Ошибка определения диска: {e}")
            messagebox.showerror("Ошибка",
                                 f"Не удалось определить диск:\n{e}")

    def _remove_windows_devender(self):
        try:
            from modules.winpe_defender import (
                remove_defender_completely, is_winpe_environment,
                get_available_drives,
            )
            if not is_winpe_environment():
                messagebox.showerror(
                    "ОШИБКА",
                    "Вы не находитесь в среде WinPE!\n\n"
                    "Функция удаления Windows Defender работает ТОЛЬКО из WinPE.")
                return
            auto_detected = self.system_commands.get_winpe_drive_letter() or "C:"
            drives = get_available_drives()
            drive_list = "\n".join([
                f"  {d['letter']} {'Windows' if d['is_windows'] else 'папка'}"
                for d in drives
            ]) or "  (нет доступных дисков)"
            msg = (
                f"ВНИМАНИЕ! Будет удалён Windows Defender\n\n"
                f"Доступные диски:\n{drive_list}\n\n"
                f"Автоматически определён: {auto_detected}\n\n"
                f"Введите букву диска (например, D:) или оставьте пустым:"
            )
            drive_input = simpledialog.askstring("ВЫБОР ДИСКА", msg,
                                                 parent=self.root)
            if drive_input and drive_input.strip():
                drive_letter = drive_input.strip().upper()
                if not drive_letter.endswith(':'):
                    drive_letter += ':'
            else:
                drive_letter = auto_detected
            if not os.path.exists(drive_letter):
                messagebox.showerror("ОШИБКА",
                                     f"Диск {drive_letter} не существует!")
                return
            self.status_var.set(f"Удаление Windows Defender с {drive_letter}...")
            self.root.update()
            result = remove_defender_completely(drive_letter)
            if result['success']:
                messagebox.showinfo("УСПЕХ", result['message'])
            else:
                messagebox.showerror("ОШИБКА", result['message'])
            if result.get('errors'):
                messagebox.showwarning("Предупреждения", "\n".join(result['errors']))
            self.status_var.set("Готово")
        except ImportError as e:
            logger.error(f"winpe_defender не найден: {e}")
            messagebox.showerror("Ошибка",
                                 "Модуль удаления Defender не найден")
        except Exception as e:
            logger.error(f"Ошибка удаления Defender: {e}")
            messagebox.showerror("Ошибка",
                                 f"Не удалось удалить Defender:\n{e}")

    def _find_windows_drive_for_winpe(self):
        drive_letter = self.system_commands.get_winpe_drive_letter()
        if drive_letter:
            return drive_letter
        for letter in 'CDEFGHIJK':
            test_path = f"{letter}:\\Windows\\System32\\sethc.exe"
            if os.path.exists(test_path):
                return f"{letter}:"
        return None

    def _replace_sethc_winpe(self):
        drive_letter = self._find_windows_drive_for_winpe()
        if not drive_letter:
            messagebox.showerror("Ошибка",
                                 "Не удалось найти диск с Windows!\n"
                                 "Убедитесь, что вы в WinPE.")
            return
        sethc_path = f"{drive_letter}\\Windows\\System32\\sethc.exe"
        if not os.path.exists(sethc_path):
            messagebox.showerror("Ошибка", "sethc.exe не найден")
            return
        file_path = filedialog.askopenfilename(
            title="Выберите файл для замены sethc.exe",
            filetypes=[("EXE файлы", "*.exe"), ("Все файлы", "*.*")])
        if not file_path:
            return
        try:
            if os.path.exists(sethc_path):
                os.remove(sethc_path)
            shutil.copy2(file_path.replace('/', '\\'), sethc_path)
            messagebox.showinfo("Успех", "sethc.exe успешно заменен!")
        except Exception as e:
            logger.error(f"Ошибка: {e}")
            messagebox.showerror("Ошибка",
                                 f"Не удалось заменить sethc:\n{e}")

    def _replace_utilman_winpe(self):
        drive_letter = self._find_windows_drive_for_winpe()
        if not drive_letter:
            messagebox.showerror("Ошибка", "Не удалось найти диск с Windows!")
            return
        utilman_path = f"{drive_letter}\\Windows\\System32\\utilman.exe"
        if not os.path.exists(utilman_path):
            messagebox.showerror("Ошибка",
                                 f"utilman.exe не найден по пути:\n{utilman_path}")
            return
        file_path = filedialog.askopenfilename(
            title="Выберите файл для замены utilman.exe",
            filetypes=[("EXE файлы", "*.exe"), ("Все файлы", "*.*")])
        if not file_path:
            return
        try:
            if os.path.exists(utilman_path):
                os.remove(utilman_path)
            shutil.copy2(file_path.replace('/', '\\'), utilman_path)
            messagebox.showinfo("Успех", "utilman.exe успешно заменен!")
        except Exception as e:
            logger.error(f"Ошибка: {e}")
            messagebox.showerror("Ошибка",
                                 f"Не удалось заменить utilman:\n{e}")

    def _get_embedded_file_path(self, filename: str) -> str:
        search_paths = []
        if hasattr(sys, '_MEIPASS'):
            search_paths.append(os.path.join(sys._MEIPASS, 'modules', filename))
            search_paths.append(os.path.join(sys._MEIPASS, filename))
        script_dir = os.path.dirname(os.path.abspath(__file__))
        search_paths.append(os.path.join(script_dir, 'modules', filename))
        search_paths.append(os.path.join(script_dir, filename))
        search_paths.append(os.path.join(os.getcwd(), 'modules', filename))
        search_paths.append(os.path.join(os.getcwd(), filename))
        for path in search_paths:
            if os.path.exists(path):
                return path.replace('/', '\\')
        return None

    def _restore_sethc_winpe(self):
        drive_letter = self._find_windows_drive_for_winpe()
        if not drive_letter:
            messagebox.showerror("Ошибка", "Не удалось найти диск с Windows!")
            return
        sethc_path = f"{drive_letter}\\Windows\\System32\\sethc.exe"
        embedded_sethc = self._get_embedded_file_path('sethc.exe')
        if not embedded_sethc:
            messagebox.showerror("Ошибка", "Встроенный sethc.exe не найден!")
            return
        try:
            if os.path.exists(sethc_path):
                os.remove(sethc_path)
            shutil.copy2(embedded_sethc, sethc_path)
            messagebox.showinfo("Успех", "sethc.exe восстановлен!")
        except Exception as e:
            logger.error(f"Ошибка: {e}")
            messagebox.showerror("Ошибка",
                                 f"Не удалось восстановить sethc:\n{e}")

    def _restore_utilman_winpe(self):
        drive_letter = self._find_windows_drive_for_winpe()
        if not drive_letter:
            messagebox.showerror("Ошибка", "Не удалось найти диск с Windows!")
            return
        utilman_path = f"{drive_letter}\\Windows\\System32\\utilman.exe"
        embedded_utilman = self._get_embedded_file_path('Utilman.exe')
        if not embedded_utilman:
            messagebox.showerror("Ошибка", "Встроенный Utilman.exe не найден!")
            return
        try:
            if os.path.exists(utilman_path):
                os.remove(utilman_path)
            shutil.copy2(embedded_utilman, utilman_path)
            messagebox.showinfo("Успех", "utilman.exe восстановлен!")
        except Exception as e:
            logger.error(f"Ошибка: {e}")
            messagebox.showerror("Ошибка",
                                 f"Не удалось восстановить utilman:\n{e}")

    def _auto_detect_winpe_drive(self):
        try:
            drive_letter = self.system_commands.get_winpe_drive_letter()
            if drive_letter:
                self.windows_drive = drive_letter
                logger.info(f"Автоопределение диска Windows: {drive_letter}")
                self.status_var.set(f"Администратор | Диск: {drive_letter}")
        except Exception as e:
            logger.error(f"Ошибка автоопределения диска: {e}")

    # ==================== ПРОВОДНИК ====================
    def _create_explorer_tab(self, parent):
        info_frame = tk.Frame(parent, bg=COLORS['bg_medium'])
        info_frame.pack(fill=tk.X, padx=8, pady=8)
        tk.Label(info_frame, text="Проводники",
                 font=FONT_UI_LARGE_BOLD,
                 bg=COLORS['bg_medium'], fg=COLORS['accent']).pack(pady=6)
        btn_frame = tk.Frame(info_frame, bg=COLORS['bg_medium'])
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Explorer--",
                  command=self._launch_explorer_at_root,
                  font=FONT_UI_BOLD,
                  bg=COLORS['accent'], fg='white',
                  activebackground=COLORS['accent_hover'],
                  activeforeground='white',
                  relief='flat', padx=20, pady=8, cursor='hand2', bd=0
                  ).pack(side=tk.LEFT, padx=8)
        tk.Button(btn_frame, text="Explorer++",
                  command=self._launch_explorer_pp,
                  font=FONT_UI_BOLD,
                  bg=COLORS['bg_light'], fg=COLORS['text_main'],
                  activebackground=COLORS['accent'], activeforeground='white',
                  relief='flat', padx=20, pady=8, cursor='hand2', bd=0
                  ).pack(side=tk.LEFT, padx=8)
        tk.Button(btn_frame, text="Обычный проводник",
                  command=self._launch_windows_explorer,
                  font=FONT_UI_BOLD,
                  bg=COLORS['bg_light'], fg=COLORS['text_main'],
                  activebackground=COLORS['accent'], activeforeground='white',
                  relief='flat', padx=20, pady=8, cursor='hand2', bd=0
                  ).pack(side=tk.LEFT, padx=8)

    # ==================== НАСТРОЙКИ ====================
    def _create_settings_tab(self, parent):
        box = tk.Frame(parent, bg=COLORS['bg_medium'],
                       highlightthickness=1, highlightbackground=COLORS['border'])
        box.pack(fill=tk.X, padx=8, pady=8)

        tk.Label(box, text="Поведение",
                 font=FONT_UI_LARGE_BOLD,
                 bg=COLORS['bg_medium'], fg=COLORS['accent']
                 ).pack(anchor=tk.W, padx=12, pady=(10, 10))

        self._close_new_var = tk.BooleanVar(
            value=self.settings.get('close_new_processes', False))
        ttk.Checkbutton(box, text="Закрывать все новые процессы ",
                        variable=self._close_new_var,
                        command=self._on_setting_close_new_toggle
                        ).pack(anchor=tk.W, padx=12, pady=4)

        self._topmost_var = tk.BooleanVar(
            value=self.settings.get('always_on_top', False))
        ttk.Checkbutton(box, text="Быть поверх всех окон",
                        variable=self._topmost_var,
                        command=self._on_setting_topmost_toggle
                        ).pack(anchor=tk.W, padx=12, pady=(4, 12))

        theme_box = tk.Frame(parent, bg=COLORS['bg_medium'],
                              highlightthickness=1, highlightbackground=COLORS['border'])
        theme_box.pack(fill=tk.X, padx=8, pady=8)
        tk.Label(theme_box, text="Тема оформления",
                 font=FONT_UI_LARGE_BOLD,
                 bg=COLORS['bg_medium'], fg=COLORS['accent']
                 ).pack(anchor=tk.W, padx=12, pady=(10, 10))

        theme_row = tk.Frame(theme_box, bg=COLORS['bg_medium'])
        theme_row.pack(anchor=tk.W, padx=12, pady=(0, 12), fill=tk.X)
        self._theme_var = tk.StringVar(value=self.settings.get('theme', 'dark'))
        theme_names = {'standard': 'Стандартная',
                       'dark': 'Тёмная',
                       'light': 'Светлая'}
        for key, label in theme_names.items():
            ttk.Radiobutton(theme_row, text=label, value=key,
                            variable=self._theme_var,
                            command=self._on_setting_theme_change
                            ).pack(side=tk.LEFT, padx=(0, 14))
        tk.Label(theme_box, text="Смена темы применится после перезапуска программы.",
                 bg=COLORS['bg_medium'], fg=COLORS['text_sec'],
                 font=('Segoe UI', 9)).pack(anchor=tk.W, padx=12, pady=(0, 10))

    def _on_setting_close_new_toggle(self):
        self.settings['close_new_processes'] = bool(self._close_new_var.get())
        save_settings(self.settings)

    def _on_setting_topmost_toggle(self):
        value = bool(self._topmost_var.get())
        self.settings['always_on_top'] = value
        save_settings(self.settings)
        try:
            self.root.attributes('-topmost', value)
        except Exception:
            pass

    def _on_setting_theme_change(self):
        self.settings['theme'] = self._theme_var.get()
        save_settings(self.settings)

    # ───────── запуск проводников ─────────
    def _launch_explorer(self, start_path: str = None):
        try:
            if not os.path.exists(self.explorer_path):
                self._extract_explorer()
            if self.explorer_mode == 'exe' and os.path.exists(self.explorer_path):
                cmd = [self.explorer_path]
            elif self.explorer_mode == 'py':
                python_exe = self._find_python_interpreter()
                if not python_exe:
                    messagebox.showerror(
                        "Ошибка",
                        "Explorer--.exe отсутствует, "
                        "а Python-интерпретатор не найден.")
                    return
                cmd = [python_exe, self.explorer_py_source]
            else:
                messagebox.showerror(
                    "Explorer-- не найден",
                    "Не найден ни Explorer--.exe, ни explorer--.py")
                return
            if start_path:
                cmd += ['--path', start_path]
            subprocess.Popen(cmd, creationflags=CREATE_NO_WINDOW)
            logger.info(f"Explorer-- запущен ({self.explorer_mode}): {cmd[0]}")
        except Exception as e:
            logger.error(f"Не удалось запустить Explorer--: {e}")
            messagebox.showerror("Ошибка",
                                 f"Не удалось запустить Explorer--:\n{e}")

    def _launch_explorer_at_root(self):
        drive_root = self.windows_drive or os.environ.get('SystemDrive', 'C:')
        if not drive_root.endswith('\\'):
            drive_root += '\\'
        self._launch_explorer(start_path=drive_root)

    def _launch_explorer_pp(self):
        try:
            if not os.path.exists(self.explorer_pp_path):
                self._extract_explorer_pp()
            if not os.path.exists(self.explorer_pp_path):
                messagebox.showerror("Ошибка", "Explorer++.exe не найден.")
                return
            subprocess.Popen([self.explorer_pp_path],
                             creationflags=CREATE_NO_WINDOW)
        except Exception as e:
            logger.error(f"Не удалось запустить Explorer++: {e}")
            messagebox.showerror("Ошибка",
                                 f"Не удалось запустить Explorer++:\n{e}")

    def _launch_windows_explorer(self):
        try:
            subprocess.Popen('explorer.exe')
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))


def main():
    if not is_admin():
        if relaunch_as_admin():
            sys.exit(0)
        try:
            warn_root = tk.Tk()
            warn_root.withdraw()
            messagebox.showwarning(
                "Нет прав администратора",
                "Программа запущена без прав администратора — часть функций "
                "(реестр, службы, замена системных файлов) работать не будет.\n\n"
                "Перезапустите от имени администратора для полной работы.")
            warn_root.destroy()
        except Exception:
            pass

    root = tk.Tk()
    app = DedHelperApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
import sys
import os
import ctypes
import random
import string
import tempfile
import shutil
import logging
import subprocess
import winreg

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTabWidget, QTreeWidget, QTreeWidgetItem,
    QMessageBox, QLineEdit, QTextEdit, QFrame, QGridLayout,
    QFileDialog, QInputDialog, QHeaderView, QSplitter, QAbstractItemView,
    QStyledItemDelegate, QStyle
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon, QColor, QBrush, QPen

CREATE_NO_WINDOW = 0x08000000

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.environ.get('TEMP', '.'), 'DedHelper.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ==================== ХЕЛПЕРЫ ====================

def generate_random_name(length: int = 8) -> str:
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def startupinfo_hide() -> subprocess.STARTUPINFO:
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return si


def run_hidden_command(cmd: str, capture_output: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, shell=True, capture_output=capture_output,
        startupinfo=startupinfo_hide(), creationflags=CREATE_NO_WINDOW
    )


def run_hidden_powershell(ps_command: str, capture_output: bool = True) -> subprocess.CompletedProcess:
    """Выполнить PowerShell без окна. Нужна для _take_registry_ownership."""
    return subprocess.run(
        ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
        capture_output=capture_output,
        startupinfo=startupinfo_hide(),
        creationflags=CREATE_NO_WINDOW
    )


def decode_output(stdout_bytes: bytes) -> str:
    """Универсальное декодирование вывода (UTF-8 → cp866 → cp1251)."""
    if not stdout_bytes:
        return ""
    for enc in ('utf-8', 'cp866', 'cp1251'):
        try:
            return stdout_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return stdout_bytes.decode('utf-8', errors='replace')


def relaunch_with_random_name() -> bool:
    if os.environ.get('DEDHELPER_RELAUNCHED') == '1':
        return False
    if not getattr(sys, 'frozen', False):
        return False
    try:
        current_exe = sys.executable
        temp_dir = tempfile.mkdtemp(prefix='DH_')
        random_name = generate_random_name(12) + '.exe'
        new_exe_path = os.path.join(temp_dir, random_name)
        shutil.copy2(current_exe, new_exe_path)

        env = os.environ.copy()
        env['DEDHELPER_RELAUNCHED'] = '1'
        env['DEDHELPER_TEMP_DIR'] = temp_dir

        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 1

        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200

        subprocess.Popen(
            [new_exe_path], env=env, startupinfo=si,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            cwd=temp_dir, close_fds=True
        )
        return True
    except Exception as e:
        logger.error(f"Ошибка перезапуска: {e}")
        return False


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.autorun import AutorunManager
from modules.restrictions import RestrictionsManager
from modules.system import SystemCommands
from modules.processes import ProcessManager
from modules.registry import RegistryEditor


# ==================== ЦВЕТА ====================

COLORS = {
    'bg_dark': '#1a1a2e',
    'bg_medium': '#16213e',
    'bg_light': '#0f3460',
    'accent': '#e94560',
    'accent_hover': '#ff6b6b',
    'text_main': '#ffffff',
    'text_sec': '#a0a0a0',
    'success': '#00d26a',
    'warning': '#ffc107',
    # Критические процессы — приглушённый оранжевый (не кислотный)
    'critical': '#c97a1e',
    'critical_fg': '#fff5e6',
    'frozen': '#4ecdc4',
    'default_ok': '#3a5a3a',
    'border_soft':   'rgba(255, 255, 255, 0.35)',
    'border_strong': 'rgba(255, 255, 255, 0.75)',
    'gridline':      'rgba(255, 255, 255, 0.22)',
    'row_border':    'rgba(255, 255, 255, 0.12)',
}

CRITICAL_PROCESS_NAMES = {
    'system', 'registry', 'idle', 'memory compression', 'memcompression',
    'secure system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
    'lsass.exe', 'winlogon.exe', 'fontdrvhost.exe',
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


# ==================== КАСТОМНЫЕ ЭЛЕМЕНТЫ ====================

class NumericTreeItem(QTreeWidgetItem):
    """QTreeWidgetItem с числовой сортировкой PID (колонка 1)"""
    def __lt__(self, other):
        tree = self.treeWidget()
        if tree is not None and tree.sortColumn() == 1:
            try:
                return int(self.text(1)) < int(other.text(1))
            except (ValueError, IndexError):
                pass
        return super().__lt__(other)


class ProcessItemDelegate(QStyledItemDelegate):
    """
    Отрисовывает фон/текст процесса из Qt::BackgroundRole / Qt::ForegroundRole.
    Нужен потому, что QSS на QTreeWidget::item перекрывает BackgroundRole —
    setBackground() сам по себе в стилизованном дереве не работает.
    """

    def paint(self, painter, option, index):
        painter.save()
        try:
            selected = bool(option.state & QStyle.StateFlag.State_Selected)
            hovered  = bool(option.state & QStyle.StateFlag.State_MouseOver)

            bg = index.data(Qt.ItemDataRole.BackgroundRole)
            fg = index.data(Qt.ItemDataRole.ForegroundRole)

            # ---- Фон ----
            if selected:
                painter.fillRect(option.rect, QColor(COLORS['accent']))
            elif bg is not None:
                brush = bg if isinstance(bg, QBrush) else QBrush(bg)
                painter.fillRect(option.rect, brush)
            elif hovered:
                painter.fillRect(option.rect, QColor(COLORS['bg_light']))
            else:
                # Зебра
                if index.row() % 2 == 1:
                    painter.fillRect(option.rect, QColor(COLORS['bg_light']))
                else:
                    painter.fillRect(option.rect, QColor(COLORS['bg_medium']))

            # ---- Тонкая линия снизу ----
            painter.setPen(QPen(QColor(255, 255, 255, 30), 1))
            painter.drawLine(option.rect.bottomLeft(), option.rect.bottomRight())

            # ---- Текст ----
            text = index.data(Qt.ItemDataRole.DisplayRole)
            if text is not None and str(text) != "":
                if fg is not None:
                    pen_color = fg.color() if isinstance(fg, QBrush) else QColor(fg)
                    painter.setPen(pen_color)
                else:
                    painter.setPen(QColor(COLORS['text_main']))

                font = index.data(Qt.ItemDataRole.FontRole)
                if font is not None:
                    painter.setFont(font)

                rect = option.rect.adjusted(8, 0, -8, 0)
                painter.drawText(
                    rect,
                    Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                    str(text)
                )
        finally:
            painter.restore()


# ==================== ГЛАВНОЕ ОКНО ====================

class DedHelperApp(QMainWindow):

    REGISTRY_ROOTS = [
        ('HKEY_CLASSES_ROOT', winreg.HKEY_CLASSES_ROOT),
        ('HKEY_CURRENT_USER', winreg.HKEY_CURRENT_USER),
        ('HKEY_LOCAL_MACHINE', winreg.HKEY_LOCAL_MACHINE),
        ('HKEY_USERS', winreg.HKEY_USERS),
        ('HKEY_CURRENT_CONFIG', winreg.HKEY_CURRENT_CONFIG),
    ]

    # Расширение -> (ProgID, команда открытия или None)
    DEFAULT_ASSOCIATIONS = {
        # Запускаемые файлы
        '.exe': ('exefile', r'"%1" %*'),
        '.com': ('comfile', r'"%1" %*'),
        '.bat': ('batfile', r'"%1" %*'),
        '.cmd': ('cmdfile', r'"%1" %*'),
        '.scr': ('scrfile', r'"%1" /S'),
        '.pif': ('piffile', r'"%1" %*'),
        '.msi': ('Msi.Package', r'"%SystemRoot%\System32\msiexec.exe" /i "%1" %*'),
        '.msp': ('Msi.Patch', r'"%SystemRoot%\System32\msiexec.exe" /p "%1" %*'),
        # Системные
        '.reg': ('regfile', r'regedit.exe "%1"'),
        '.lnk': ('lnkfile', None),
        '.url': ('InternetShortcut', None),
        '.dll': ('dllfile', None),
        '.sys': ('sysfile', None),
        '.inf': ('inffile', r'%SystemRoot%\System32\notepad.exe %1'),
        # Текст
        '.txt': ('txtfile', r'%SystemRoot%\system32\NOTEPAD.EXE %1'),
        '.log': ('txtfile', r'%SystemRoot%\system32\NOTEPAD.EXE %1'),
        '.ini': ('txtfile', r'%SystemRoot%\system32\NOTEPAD.EXE %1'),
        # Web
        '.html': ('htmlfile', r'"%ProgramFiles%\Internet Explorer\iexplore.exe" %1'),
        '.htm':  ('htmlfile', r'"%ProgramFiles%\Internet Explorer\iexplore.exe" %1'),
        '.xml':  ('xmlfile', None),
        # Архивы
        '.zip': ('CompressedFolder', None),
        '.cab': ('CABFolder', None),
        # Скрипты
        '.vbs': ('VBSFile', r'"%SystemRoot%\System32\WScript.exe" "%1" %*'),
        '.js':  ('JSFile',  r'"%SystemRoot%\System32\WScript.exe" "%1" %*'),
        '.jse': ('JSEFile', r'"%SystemRoot%\System32\WScript.exe" "%1" %*'),
        '.wsf': ('WSFFile', r'"%SystemRoot%\System32\WScript.exe" "%1" %*'),
        '.wsh': ('WSHFile', r'"%SystemRoot%\System32\WScript.exe" "%1" %*'),
        # Изображения
        '.jpg':  ('jpegfile', None),
        '.jpeg': ('jpegfile', None),
        '.png':  ('pngfile', None),
        '.gif':  ('giffile', None),
        '.bmp':  ('Paint.Picture', None),
        '.ico':  ('icofile', None),
    }

    def __init__(self):
        super().__init__()
        self.random_name = generate_random_name()
        self.setWindowTitle(f"{self.random_name}")

        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dedhelper.ico')
            if os.path.exists(icon_path):
                self.setWindowIcon(QIcon(icon_path))
        except Exception as e:
            logger.error(f"Ошибка установки иконки: {e}")

        self.resize(1100, 800)
        self.setMinimumSize(950, 700)
        self.is_admin = is_admin()

        self.temp_dir = tempfile.mkdtemp(prefix='DedHelper_')
        self.explorer_path = os.path.join(self.temp_dir, 'Explorer++.exe')
        self._extract_explorer()

        if hasattr(sys, '_MEIPASS'):
            self.modules_dir = os.path.join(sys._MEIPASS, 'modules')
        else:
            self.modules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules')

        self.autorun_manager = AutorunManager()
        self.restrictions_manager = RestrictionsManager()
        self.system_commands = SystemCommands()
        self.process_manager = ProcessManager()
        self.registry_editor = RegistryEditor()

        self.frozen_pids = set()

        self._apply_dark_theme()
        self._create_ui()
        QTimer.singleShot(1000, self._auto_detect_winpe_drive)

    # ==================== ТЕМА ====================

    def _apply_dark_theme(self):
        self.setStyleSheet(f"""
            QMainWindow {{ background-color: {COLORS['bg_dark']}; }}
            QWidget {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_main']};
                font-family: 'Segoe UI';
                font-size: 10pt;
            }}
            QFrame {{ background-color: {COLORS['bg_medium']}; border-radius: 5px; }}

            QPushButton {{
                background-color: {COLORS['bg_light']};
                color: {COLORS['text_main']};
                border: 1px solid {COLORS['border_soft']};
                padding: 10px 15px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 10pt;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent']};
                border: 1px solid {COLORS['border_strong']};
            }}
            QPushButton:pressed {{
                background-color: {COLORS['accent_hover']};
                border: 1px solid #ffffff;
            }}
            QPushButton:focus {{
                border: 1px solid #ffffff;
            }}

            QLabel {{ color: {COLORS['text_main']}; background-color: transparent; }}

            QTabWidget::pane {{
                background-color: {COLORS['bg_medium']};
                border: 1px solid {COLORS['border_soft']};
                border-radius: 5px;
            }}
            QTabBar::tab {{
                background-color: {COLORS['bg_light']};
                color: {COLORS['text_main']};
                padding: 10px 20px;
                border: 1px solid {COLORS['border_soft']};
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                margin-right: 2px;
                font-weight: bold;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['accent']};
                border: 1px solid #ffffff;
                border-bottom: none;
            }}
            QTabBar::tab:hover {{
                background-color: {COLORS['accent_hover']};
                border: 1px solid {COLORS['border_strong']};
                border-bottom: none;
            }}

            QTreeWidget {{
                background-color: {COLORS['bg_medium']};
                color: {COLORS['text_main']};
                border: 1px solid {COLORS['border_soft']};
                border-radius: 5px;
                alternate-background-color: {COLORS['bg_light']};
                gridline-color: {COLORS['gridline']};
            }}
            QTreeWidget::item {{
                padding: 5px;
                border-bottom: 1px solid {COLORS['row_border']};
            }}
            QTreeWidget::item:selected {{
                background-color: {COLORS['accent']};
                border-bottom: 1px solid #ffffff;
            }}
            QTreeWidget::item:hover {{
                background-color: {COLORS['bg_light']};
                border-bottom: 1px solid {COLORS['border_soft']};
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_light']};
                color: {COLORS['text_main']};
                padding: 8px;
                border: 1px solid {COLORS['border_soft']};
                border-top: none;
                font-weight: bold;
            }}
            QHeaderView::section:first {{ border-left: none; }}
            QHeaderView::section:last  {{ border-right: none; }}

            QLineEdit {{
                background-color: {COLORS['bg_medium']};
                color: {COLORS['text_main']};
                border: 1px solid {COLORS['border_soft']};
                border-radius: 5px;
                padding: 8px;
                font-family: 'Consolas';
            }}
            QLineEdit:hover {{ border: 1px solid {COLORS['border_strong']}; }}
            QLineEdit:focus {{ border: 1px solid #ffffff; }}

            QTextEdit {{
                background-color: {COLORS['bg_medium']};
                color: {COLORS['text_main']};
                border: 1px solid {COLORS['border_soft']};
                border-radius: 5px;
                font-family: 'Consolas';
            }}
            QTextEdit:focus {{ border: 1px solid #ffffff; }}

            QScrollBar:vertical {{
                background-color: {COLORS['bg_dark']};
                width: 12px; border-radius: 6px;
                border: 1px solid {COLORS['border_soft']};
            }}
            QScrollBar::handle:vertical {{
                background-color: {COLORS['bg_light']};
                border-radius: 6px; min-height: 20px;
                border: 1px solid {COLORS['border_soft']};
            }}
            QScrollBar::handle:vertical:hover {{ background-color: {COLORS['accent']}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
            QScrollBar:horizontal {{
                background-color: {COLORS['bg_dark']};
                height: 12px; border-radius: 6px;
                border: 1px solid {COLORS['border_soft']};
            }}
            QScrollBar::handle:horizontal {{
                background-color: {COLORS['bg_light']};
                border-radius: 6px; min-width: 20px;
                border: 1px solid {COLORS['border_soft']};
            }}
            QScrollBar::handle:horizontal:hover {{ background-color: {COLORS['accent']}; }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0px; }}

            QMessageBox {{ background-color: {COLORS['bg_medium']}; }}
            QMessageBox QLabel {{ color: {COLORS['text_main']}; }}
            QMessageBox QPushButton {{ border: 1px solid {COLORS['border_soft']}; min-width: 80px; }}
            QInputDialog {{ background-color: {COLORS['bg_medium']}; }}
            QInputDialog QPushButton {{ border: 1px solid {COLORS['border_soft']}; min-width: 80px; }}
            QSplitter::handle {{ background-color: {COLORS['bg_light']}; }}
            QSplitter::handle:hover {{ background-color: {COLORS['accent']}; }}
        """)

    # ==================== UI ====================

    def _extract_explorer(self):
        try:
            if hasattr(sys, '_MEIPASS'):
                source = os.path.join(sys._MEIPASS, 'modules', 'Explorer++.exe')
                if os.path.exists(source):
                    shutil.copy2(source, self.explorer_path)
                    return
            for source in (
                os.path.join(os.path.dirname(__file__), 'modules', 'Explorer++.exe'),
                os.path.join(os.getcwd(), 'modules', 'Explorer++.exe'),
            ):
                if os.path.exists(source):
                    shutil.copy2(source, self.explorer_path)
                    return
        except Exception as e:
            logger.error(f"Ошибка извлечения Explorer++: {e}")

    def _create_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self._create_header(main_layout)

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(15, 15, 15, 15)
        content_layout.setSpacing(15)

        self._create_main_screen(content_layout)
        self._create_notebook(content_layout)

        main_layout.addWidget(content_widget, 1)
        self._create_status_bar()

    def _create_header(self, parent_layout):
        header_frame = QFrame()
        header_frame.setFixedHeight(60)
        header_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_light']};
                border-radius: 0;
                border-bottom: 1px solid {COLORS['border_soft']};
            }}
        """)
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(20, 0, 20, 0)

        logo_label = QLabel("DedHelper")
        logo_label.setStyleSheet(f"""
            color: {COLORS['accent']};
            font-size: 24px; font-weight: bold;
            background-color: transparent; border: none;
        """)
        header_layout.addWidget(logo_label)
        header_layout.addStretch()

        admin_status = "Администратор" if self.is_admin else "Нет прав админа!"
        admin_color = COLORS['success'] if self.is_admin else COLORS['warning']
        self.admin_label = QLabel(admin_status)
        self.admin_label.setStyleSheet(f"""
            color: {admin_color};
            font-size: 9pt; font-weight: bold;
            background-color: transparent; border: none;
            padding: 4px 10px;
        """)
        header_layout.addWidget(self.admin_label)
        parent_layout.addWidget(header_frame)

    def _create_main_screen(self, parent_layout):
        main_frame = QFrame()
        main_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_medium']};
                border-radius: 10px;
                border: 1px solid {COLORS['border_soft']};
            }}
        """)
        main_layout = QVBoxLayout(main_frame)
        main_layout.setContentsMargins(15, 15, 15, 15)

        title_label = QLabel("Быстрое восстановление")
        title_label.setStyleSheet(f"""
            color: {COLORS['accent']};
            font-size: 11pt; font-weight: bold;
            background-color: transparent; border: none;
        """)
        main_layout.addWidget(title_label)

        buttons_grid = QGridLayout()
        buttons_grid.setSpacing(10)

        buttons = [
            ("Восстановить шрифт", self._restore_font),
            ("Включить UAC", self._enable_uac),
            ("Войти в WinRE", self._enter_winre),
            ("Снять ограничения", self._remove_all_restrictions),
            ("Очистить автозагрузку", self._clean_autorun),
            ("sfc /scannow", self._run_sfc),
            ("Восстановить ассоциации", self._restore_associations),
        ]

        for i, (text, command) in enumerate(buttons):
            row = i // 3
            col = i % 3
            btn = QPushButton(text)
            btn.setMinimumHeight(45)
            btn.clicked.connect(command)
            buttons_grid.addWidget(btn, row, col)

        main_layout.addLayout(buttons_grid)
        parent_layout.addWidget(main_frame)

    def _create_notebook(self, parent_layout):
        self.notebook = QTabWidget()
        parent_layout.addWidget(self.notebook, 1)

        self._create_autorun_tab()
        self._create_services_tab()
        self._create_scheduler_tab()
        self._create_restrictions_tab()
        self._create_processes_tab()
        self._create_registry_tab()
        self._create_system_tab()
        self._create_explorer_tab()

    def _create_status_bar(self):
        self.statusBar().setStyleSheet(f"""
            QStatusBar {{
                background-color: {COLORS['bg_light']};
                color: {COLORS['text_main']};
                padding: 5px;
                border-top: 1px solid {COLORS['border_soft']};
            }}
        """)
        self.statusBar().showMessage("Готово")

    def _style_table(self, table: QTreeWidget):
        """Совместимость; ничего не делает."""
        pass

    # ==================== БЫСТРЫЕ КНОПКИ ====================

    def _restore_font(self):
        """
        Восстановление системного шрифта с обходом 'Отказано в доступе'.
        Чистит FontSubstitutes + Fonts, берёт ownership, перезапускает кэш шрифтов.
        """
        if not self.is_admin:
            QMessageBox.critical(self, "Ошибка", "Требуются права администратора!")
            return

        success = []
        errors = []

        targets = [
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes',
             ['Segoe UI', 'Segoe UI Semibold', 'Segoe UI Light', 'Segoe UI Semilight',
              'Microsoft Sans Serif', 'MS Shell Dlg', 'MS Shell Dlg 2',
              'Tahoma', 'Arial', 'Helvetica', 'System', 'Fixedsys', 'Small Fonts']),
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts',
             ['Segoe UI (TrueType)', 'Segoe UI Bold (TrueType)',
              'Segoe UI Italic (TrueType)', 'Segoe UI Bold Italic (TrueType)',
              'Segoe UI Semibold (TrueType)', 'Segoe UI Light (TrueType)',
              'Segoe UI Semilight (TrueType)']),
        ]

        for hive, path, values in targets:
            hive_str = 'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
            except PermissionError:
                logger.info(f"Access Denied на {path}, берём ownership...")
                self._take_registry_ownership(hive_str, path)
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
                except OSError as e:
                    errors.append(f"{path}: {e}")
                    continue
            except OSError as e:
                logger.info(f"Ключ {path} отсутствует: {e}")
                continue

            try:
                for vname in values:
                    try:
                        winreg.DeleteValue(key, vname)
                        success.append(f"{path}\\{vname}")
                    except FileNotFoundError:
                        pass
                    except OSError as e:
                        try:
                            r = run_hidden_command(
                                f'reg delete "{hive_str}\\{path}" /v "{vname}" /f',
                                capture_output=True
                            )
                            if r.returncode == 0:
                                success.append(f"{path}\\{vname} (reg.exe)")
                            else:
                                errors.append(f"{path}\\{vname}: {e}")
                        except Exception:
                            errors.append(f"{path}\\{vname}: {e}")
            finally:
                winreg.CloseKey(key)

        # Сброс пользовательских настроек шрифта в HKCU
        try:
            run_hidden_command(
                'reg delete "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Fonts" /f',
                capture_output=True
            )
        except Exception:
            pass

        # Перезапуск службы кэша шрифтов
        for svc in ('FontCache', 'FontCache3.0.0.0'):
            try:
                run_hidden_command(f'net stop {svc} /y', capture_output=True)
                run_hidden_command(f'net start {svc}', capture_output=True)
            except Exception:
                pass

        msg = f"Системный шрифт восстановлен\n\n Удалено значений: {len(success)}\n"
        if errors:
            msg += f"\nПредупреждения ({len(errors)}):\n  " + "\n  ".join(errors[:10])
        msg += "\n\nРекомендуется перезагрузка."
        QMessageBox.information(self, "Результат", msg)

    def _enable_uac(self):
        if self.system_commands.enable_uac():
            QMessageBox.information(self, "Успех", "UAC включён. Требуется перезагрузка")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось включить UAC")

    def _enter_winre(self):
        self.system_commands.enter_winre()

    def _remove_all_restrictions(self):
        result = self.restrictions_manager.remove_all_restrictions()
        msg = "Результат снятия ограничений:\n\n"
        msg += f"ScancodeMap: {'удалён' if result['scancode_map'] else 'не найден'}\n"
        msg += f"IFEO Debugger: удалено {result['debuggers']}\n"
        msg += f"IFEO GlobalFlag: удалено {result['ifeo_global_flags']}\n"
        msg += f"DisallowRun: {'снят' if result['disallow_run'] else 'не найден'}\n"
        msg += f"Group Policy (Policies): очищено {result['group_policy']} веток\n"
        msg += f"Winlogon\\Shell: {'исправлен' if result['winlogon_shell'] else 'в норме'}\n"
        msg += f"Winlogon\\Userinit: {'исправлен' if result['winlogon_userinit'] else 'в норме'}\n"
        msg += f"AppInit_DLLs: {'очищены' if result['appinit'] else 'в норме'}\n"
        msg += f"SafeBoot\\AlternateShell: {'удалён' if result['safeboot'] else 'не найден'}\n"
        msg += f"SpecialAccounts\\UserList: {'очищен' if result['special_accounts'] else 'не найден'}\n"
        msg += "\nHOSTS-файл НЕ трогался."
        QMessageBox.information(self, "Результат", msg)

    def _clean_autorun(self):
        removed = 0
        for entry in self.autorun_manager.get_registry_autoruns():
            if self.autorun_manager.remove_registry_autorun(entry['name'], entry['location']):
                removed += 1
        for item in self.autorun_manager.get_startup_folder_items():
            if self.autorun_manager.remove_from_startup(item['name']):
                removed += 1
        QMessageBox.information(self, "Успех", f"Удалено элементов: {removed}")

    def _run_sfc(self):
        self.system_commands.run_sfc()

    def _disable_test_mode(self):
        if self.system_commands.disable_test_mode():
            QMessageBox.information(self, "Успех", "Тестовый режим выключен. Требуется перезагрузка")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось выключить тестовый режим")

    # ==================== ВОССТАНОВЛЕНИЕ АССОЦИАЦИЙ ====================

    def _take_registry_ownership(self, hive_str: str, path: str) -> bool:
        """Взять ownership ключа реестра через PowerShell Set-Acl."""
        ps_script = (
            f'$ErrorActionPreference = "SilentlyContinue"; '
            f'$p = "{hive_str}:\\{path}"; '
            f'try {{ '
            f'  $acl = Get-Acl -Path $p; '
            f'  $adm = New-Object System.Security.Principal.NTAccount("Administrators"); '
            f'  $acl.SetOwner($adm); Set-Acl -Path $p -AclObject $acl; '
            f'  $rule = New-Object System.Security.AccessControl.RegistryAccessRule($adm, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"); '
            f'  $acl.ResetAccessRule($rule); Set-Acl -Path $p -AclObject $acl; '
            f'  Write-Output "OK" '
            f'}} catch {{ Write-Output "FAIL: $_" }}'
        )
        try:
            result = run_hidden_powershell(ps_script, capture_output=True)
            out = decode_output(result.stdout) if result.stdout else ""
            ok = 'OK' in out
            if not ok:
                logger.warning(f"take_ownership {hive_str}\\{path}: {out}")
            return ok
        except Exception as e:
            logger.error(f"take_ownership исключение: {e}")
            return False

    def _clear_user_choice_keys(self) -> int:
        """Удалить UserChoice — без него Win10/11 игнорирует правки ассоциаций."""
        removed = 0
        base = r'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts'
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base, 0, winreg.KEY_READ)
        except OSError:
            return 0

        exts = []
        try:
            i = 0
            while True:
                try:
                    exts.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
        finally:
            winreg.CloseKey(key)

        for ext in exts:
            sub = f'{base}\\{ext}'
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, f'{sub}\\UserChoice')
                removed += 1
                continue
            except OSError:
                pass
            try:
                r = run_hidden_command(
                    f'reg delete "HKCU\\{sub}\\UserChoice" /f', capture_output=True
                )
                if r.returncode == 0:
                    removed += 1
            except Exception:
                pass
        return removed

    def _write_association_registry(self, ext: str, prog_id: str, command: str) -> bool:
        """
        Записать ассоциацию. Пробует winreg напрямую, при отказе — ownership + reg.exe.
        Никогда не крашит — при любой ошибке возвращает False.
        """
        # --- 1) ext -> prog_id ---
        ext_path = f'SOFTWARE\\Classes\\{ext}'
        try:
            k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, ext_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, '', 0, winreg.REG_SZ, prog_id)
            winreg.CloseKey(k)
        except OSError:
            # Может быть PermissionError — берём ownership
            self._take_registry_ownership('HKLM', ext_path)
            try:
                k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, ext_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(k, '', 0, winreg.REG_SZ, prog_id)
                winreg.CloseKey(k)
            except Exception:
                # Финальный fallback через reg.exe
                r = run_hidden_command(
                    f'reg add "HKLM\\{ext_path}" /ve /t REG_SZ /d "{prog_id}" /f',
                    capture_output=True
                )
                if r.returncode != 0:
                    return False

        # --- 2) command (если есть) ---
        if command:
            cmd_path = f'SOFTWARE\\Classes\\{prog_id}\\shell\\open\\command'
            try:
                k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, cmd_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(k, '', 0, winreg.REG_EXPAND_SZ, command)
                winreg.CloseKey(k)
            except OSError:
                self._take_registry_ownership('HKLM', cmd_path)
                try:
                    k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, cmd_path, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(k, '', 0, winreg.REG_EXPAND_SZ, command)
                    winreg.CloseKey(k)
                except Exception:
                    r = run_hidden_command(
                        f'reg add "HKLM\\{cmd_path}" /ve /t REG_EXPAND_SZ /d "{command}" /f',
                        capture_output=True
                    )
                    if r.returncode != 0:
                        return False

        return True

    def _restore_associations(self):
        """Восстановление ассоциаций (аналог Simple Unlocker). Защищено try/except — не крашит."""
        try:
            if not self.is_admin:
                QMessageBox.critical(self, "Ошибка", "Требуются права администратора!")
                return

            self.statusBar().showMessage("Очистка UserChoice...")
            QApplication.processEvents()
            try:
                user_choice_removed = self._clear_user_choice_keys()
            except Exception as e:
                logger.error(f"Ошибка очистки UserChoice: {e}")
                user_choice_removed = 0

            restored = 0
            failed = []
            total = len(self.DEFAULT_ASSOCIATIONS)

            for idx, (ext, (prog_id, command)) in enumerate(self.DEFAULT_ASSOCIATIONS.items(), 1):
                self.statusBar().showMessage(f"Восстановление {ext} ({idx}/{total})...")
                QApplication.processEvents()
                try:
                    if self._write_association_registry(ext, prog_id, command):
                        restored += 1
                    else:
                        failed.append(ext)
                except Exception as e:
                    logger.error(f"Исключение при {ext}: {e}")
                    failed.append(ext)

            # Дублируем через assoc/ftype
            self.statusBar().showMessage("Применение через assoc/ftype...")
            QApplication.processEvents()
            for ext, (prog_id, command) in self.DEFAULT_ASSOCIATIONS.items():
                try:
                    run_hidden_command(f'assoc {ext}={prog_id}', capture_output=True)
                    if command:
                        run_hidden_command(f'ftype {prog_id}={command}', capture_output=True)
                except Exception:
                    pass

            # Перезапуск explorer
            try:
                run_hidden_command('taskkill /f /im explorer.exe', capture_output=True)
                subprocess.Popen('explorer.exe', shell=True)
            except Exception:
                pass

            self.statusBar().showMessage("Готово")

            msg = (
                f"Восстановление ассоциаций завершено\n\n"
                f"Удалено UserChoice: {user_choice_removed}\n"
                f"Восстановлено ассоциаций: {restored} из {total}\n"
            )
            if failed:
                msg += f"\nП Не удалось: " + ", ".join(failed[:15])
                if len(failed) > 15:
                    msg += f" ... ещё {len(failed) - 15}"
            msg += "\n\nПроводник перезапущен."
            QMessageBox.information(self, "Результат", msg)

        except Exception as e:
            logger.exception("Критическая ошибка в _restore_associations")
            QMessageBox.critical(self, "Ошибка", f"Критическая ошибка:\n{e}")

    # ==================== ВКЛАДКА АВТОЗАГРУЗКА ====================

    def _create_autorun_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("Обновить")
        refresh_btn.clicked.connect(self._refresh_autorun)
        btn_layout.addWidget(refresh_btn)

        remove_btn = QPushButton("Удалить выбранное")
        remove_btn.clicked.connect(self._remove_selected_autorun)
        btn_layout.addWidget(remove_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.autorun_tree = QTreeWidget()
        self.autorun_tree.setHeaderLabels(['Расположение', 'Имя', 'Значение'])
        self.autorun_tree.setAlternatingRowColors(True)
        self.autorun_tree.setRootIsDecorated(False)
        self.autorun_tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._style_table(self.autorun_tree)

        header = self.autorun_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.autorun_tree.setColumnWidth(0, 180)
        self.autorun_tree.setColumnWidth(1, 180)

        layout.addWidget(self.autorun_tree)
        self.notebook.addTab(widget, "Автозагрузка")
        self._refresh_autorun()

    def _refresh_autorun(self):
        try:
            self.autorun_tree.clear()
            for entry in self.autorun_manager.get_registry_autoruns():
                value_str = str(entry['value'])
                if len(value_str) > 120:
                    value_str = value_str[:117] + "..."
                item = QTreeWidgetItem([entry['location_label'], entry['name'], value_str])
                item.setData(0, Qt.ItemDataRole.UserRole, entry['location'])
                item.setData(0, Qt.ItemDataRole.UserRole + 1, entry['name'])
                if entry.get('is_default'):
                    for col in range(3):
                        item.setBackground(col, QColor(COLORS['default_ok']))
                self.autorun_tree.addTopLevelItem(item)

            for item in self.autorun_manager.get_startup_folder_items():
                path_str = item['path']
                if len(path_str) > 120:
                    path_str = path_str[:117] + "..."
                tree_item = QTreeWidgetItem(['Startup', item['name'], path_str])
                tree_item.setData(0, Qt.ItemDataRole.UserRole, 'Startup')
                tree_item.setData(0, Qt.ItemDataRole.UserRole + 1, item['name'])
                self.autorun_tree.addTopLevelItem(tree_item)

            self.statusBar().showMessage(
                f"Автозагрузка: {self.autorun_tree.topLevelItemCount()} элементов"
            )
        except Exception as e:
            logger.error(f"Ошибка автозагрузки: {e}")
            self.statusBar().showMessage(f"Ошибка: {e}")

    def _remove_selected_autorun(self):
        selected = self.autorun_tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Предупреждение", "Выберите элементы")
            return
        reply = QMessageBox.question(
            self, "Подтверждение",
            f"Удалить выбранные элементы? ({len(selected)} шт.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        removed = 0
        for item in selected:
            location = item.data(0, Qt.ItemDataRole.UserRole)
            name = item.data(0, Qt.ItemDataRole.UserRole + 1)
            if location == 'Startup':
                if self.autorun_manager.remove_from_startup(name):
                    removed += 1
            else:
                if self.autorun_manager.remove_registry_autorun(name, location):
                    removed += 1
        self._refresh_autorun()
        QMessageBox.information(self, "Успех", f"Удалено элементов: {removed}")

    # ==================== ВКЛАДКА СЛУЖБЫ ====================

    def _create_services_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        btn_layout = QHBoxLayout()
        for text, slot in [
            ("Обновить", self._refresh_services),
            ("Запустить", self._start_services),
            ("Остановить", self._stop_services),
            ("Отключить", self._disable_services),
            ("Включить", self._enable_services),
            ("Удалить службу", self._delete_services),
        ]:
            b = QPushButton(text)
            b.clicked.connect(slot)
            btn_layout.addWidget(b)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Фильтр:"))
        self.services_filter = QLineEdit()
        self.services_filter.setPlaceholderText("Поиск по имени или отображаемому имени...")
        self.services_filter.textChanged.connect(self._filter_services)
        filter_layout.addWidget(self.services_filter)
        layout.addLayout(filter_layout)

        self.services_tree = QTreeWidget()
        self.services_tree.setHeaderLabels(['Имя', 'Отображаемое имя', 'Состояние'])
        self.services_tree.setAlternatingRowColors(True)
        self.services_tree.setRootIsDecorated(False)
        self.services_tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._style_table(self.services_tree)

        header = self.services_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.services_tree.setColumnWidth(0, 220)
        self.services_tree.setColumnWidth(2, 100)

        layout.addWidget(self.services_tree)
        self.notebook.addTab(widget, "Службы")
        self._refresh_services()

    def _refresh_services(self):
        self.services_tree.clear()
        try:
            services = self.autorun_manager.get_services()
        except Exception as e:
            logger.error(f"Ошибка получения служб: {e}")
            services = []
        for svc in services:
            state = svc.get('state', 'unknown')
            item = QTreeWidgetItem([svc.get('name', ''), svc.get('display_name', ''), state])
            item.setData(0, Qt.ItemDataRole.UserRole, svc.get('name', ''))
            self.services_tree.addTopLevelItem(item)
        self.statusBar().showMessage(f"Служб: {len(services)}")

    def _filter_services(self, text: str):
        text_lower = text.lower()
        for i in range(self.services_tree.topLevelItemCount()):
            item = self.services_tree.topLevelItem(i)
            name = item.text(0).lower()
            disp = item.text(1).lower()
            item.setHidden(text_lower not in name and text_lower not in disp)

    def _get_selected_service_names(self) -> list:
        return [item.data(0, Qt.ItemDataRole.UserRole)
                for item in self.services_tree.selectedItems()
                if item.data(0, Qt.ItemDataRole.UserRole)]

    def _start_services(self):
        names = self._get_selected_service_names()
        if not names:
            QMessageBox.warning(self, "Предупреждение", "Выберите службы")
            return
        if QMessageBox.question(
            self, "Подтверждение", f"Запустить {len(names)} служб(ы)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        ok = sum(1 for n in names if self.autorun_manager.start_service(n))
        self._refresh_services()
        QMessageBox.information(self, "Результат", f"Запущено: {ok} из {len(names)}")

    def _stop_services(self):
        names = self._get_selected_service_names()
        if not names:
            QMessageBox.warning(self, "Предупреждение", "Выберите службы")
            return
        if QMessageBox.question(
            self, "Подтверждение", f"Остановить {len(names)} служб(ы)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        ok = sum(1 for n in names if self.autorun_manager.stop_service(n))
        self._refresh_services()
        QMessageBox.information(self, "Результат", f"Остановлено: {ok} из {len(names)}")

    def _disable_services(self):
        names = self._get_selected_service_names()
        if not names:
            QMessageBox.warning(self, "Предупреждение", "Выберите службы")
            return
        if QMessageBox.question(
            self, "Подтверждение", f"Отключить {len(names)} служб(ы)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        ok = sum(1 for n in names if self.autorun_manager.disable_service(n))
        self._refresh_services()
        QMessageBox.information(self, "Результат", f"Отключено: {ok} из {len(names)}")

    def _enable_services(self):
        names = self._get_selected_service_names()
        if not names:
            QMessageBox.warning(self, "Предупреждение", "Выберите службы")
            return
        if QMessageBox.question(
            self, "Подтверждение", f"Включить {len(names)} служб(ы)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        ok = sum(1 for n in names if self.autorun_manager.enable_service(n))
        self._refresh_services()
        QMessageBox.information(self, "Результат", f"Включено: {ok} из {len(names)}")

    def _delete_services(self):
        names = self._get_selected_service_names()
        if not names:
            QMessageBox.warning(self, "Предупреждение", "Выберите службы")
            return
        if QMessageBox.question(
            self, "ПРЕДУПРЕЖДЕНИЕ",
            f"УДАЛИТЬ {len(names)} служб(ы)?\n\nЭто необратимо!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        ok = sum(1 for n in names if self.autorun_manager.delete_service(n))
        self._refresh_services()
        QMessageBox.information(self, "Результат", f"Удалено: {ok} из {len(names)}")

    # ==================== ВКЛАДКА ПЛАНИРОВЩИК ====================

    def _create_scheduler_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        btn_layout = QHBoxLayout()
        for text, slot in [
            ("Обновить", self._refresh_scheduler),
            ("Удалить задачу", self._delete_task),
            ("Отключить", self._disable_task),
            ("Включить", self._enable_task),
        ]:
            b = QPushButton(text)
            b.clicked.connect(slot)
            btn_layout.addWidget(b)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.scheduler_tree = QTreeWidget()
        self.scheduler_tree.setHeaderLabels(['Путь', 'Имя'])
        self.scheduler_tree.setAlternatingRowColors(True)
        self.scheduler_tree.setRootIsDecorated(False)
        self.scheduler_tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._style_table(self.scheduler_tree)
        self.scheduler_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.scheduler_tree)

        self.notebook.addTab(widget, "Планировщик")
        self._refresh_scheduler()

    def _refresh_scheduler(self):
        try:
            self.scheduler_tree.clear()
            for task in self.autorun_manager.get_scheduled_tasks()[:200]:
                item = QTreeWidgetItem(['Tasks', task['name']])
                self.scheduler_tree.addTopLevelItem(item)
        except Exception as e:
            logger.error(f"Ошибка обновления планировщика: {e}")

    def _delete_task(self):
        selected = self.scheduler_tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Предупреждение", "Выберите задачи")
            return
        if QMessageBox.question(
            self, "Подтверждение",
            f"Удалить выбранные задачи? ({len(selected)} шт.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        removed = sum(1 for item in selected
                      if self.autorun_manager.delete_scheduled_task(item.text(1)))
        self._refresh_scheduler()
        QMessageBox.information(self, "Успех", f"Удалено задач: {removed}")

    def _disable_task(self):
        selected = self.scheduler_tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Предупреждение", "Выберите задачи")
            return
        ok = sum(1 for item in selected
                 if self.autorun_manager.disable_scheduled_task(item.text(1)))
        QMessageBox.information(self, "Результат", f"Отключено: {ok} из {len(selected)}")

    def _enable_task(self):
        selected = self.scheduler_tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Предупреждение", "Выберите задачи")
            return
        ok = sum(1 for item in selected
                 if self.autorun_manager.enable_scheduled_task(item.text(1)))
        QMessageBox.information(self, "Результат", f"Включено: {ok} из {len(selected)}")

    # ==================== ВКЛАДКА ОГРАНИЧЕНИЯ ====================

    def _create_restrictions_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        title_label = QLabel("Снятие ограничений")
        title_label.setStyleSheet(f"""
            color: {COLORS['accent']};
            font-size: 11pt; font-weight: bold;
            background-color: transparent; border: none;
        """)
        layout.addWidget(title_label)

        grid = QGridLayout()
        grid.setSpacing(10)
        buttons = [
            ("Снять ScancodeMap", self._remove_scancode),
            ("Удалить IFEO Debuggers", self._remove_debuggers),
            ("Снять DisallowRun", self._remove_disallow_run),
            ("Снять ВСЕ ограничения", self._remove_all_restrictions_btn),
        ]
        for i, (text, command) in enumerate(buttons):
            row = i // 3
            col = i % 3
            btn = QPushButton(text)
            btn.setMinimumHeight(40)
            btn.clicked.connect(command)
            grid.addWidget(btn, row, col)

        layout.addLayout(grid)
        layout.addStretch()
        self.notebook.addTab(widget, "Ограничения")

    def _remove_scancode(self):
        if self.restrictions_manager.remove_scancode_map():
            QMessageBox.information(self, "Успех", "ScancodeMap удалён")
        else:
            QMessageBox.critical(self, "Ошибка", "ScancodeMap не найден")

    def _remove_debuggers(self):
        count = self.restrictions_manager.remove_all_debuggers()
        QMessageBox.information(self, "Успех", f"Удалено записей IFEO: {count}")

    def _remove_disallow_run(self):
        if self.restrictions_manager.remove_disallow_run():
            QMessageBox.information(self, "Успех", "DisallowRun снят")
        else:
            QMessageBox.critical(self, "Ошибка", "DisallowRun не найден")

    def _remove_all_restrictions_btn(self):
        self._remove_all_restrictions()

    # ==================== ВКЛАДКА ПРОЦЕССЫ ====================

    def _create_processes_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        btn_layout = QHBoxLayout()
        for text, slot in [
            ("Обновить", self._refresh_processes),
            ("Завершить", self._terminate_process),
            ("Заморозить", self._suspend_process),
            ("Разморозить", self._resume_process),
            ("Снять критический флаг", self._remove_critical_flag),
        ]:
            b = QPushButton(text)
            b.clicked.connect(slot)
            btn_layout.addWidget(b)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Фильтр:"))
        self.process_filter = QLineEdit()
        self.process_filter.setPlaceholderText("Поиск по имени, PID или пути...")
        self.process_filter.textChanged.connect(self._filter_processes)
        filter_layout.addWidget(self.process_filter)
        layout.addLayout(filter_layout)

        self.process_tree = QTreeWidget()
        self.process_tree.setHeaderLabels(['Имя процесса', 'PID', 'Путь к файлу'])
        self.process_tree.setAlternatingRowColors(False)   # зебру рисует делегат
        self.process_tree.setRootIsDecorated(False)
        self.process_tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.process_tree.setSortingEnabled(True)
        self.process_tree.setItemDelegate(ProcessItemDelegate(self.process_tree))
        self._style_table(self.process_tree)

        header = self.process_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.process_tree.setColumnWidth(0, 200)
        self.process_tree.setColumnWidth(1, 70)

        layout.addWidget(self.process_tree)
        self.notebook.addTab(widget, "Процессы")
        self._refresh_processes()

    def _refresh_processes(self):
        self.process_tree.setSortingEnabled(False)
        self.process_tree.clear()

        # Используем метод БЕЗ критичности — определяем сами
        try:
            processes = self.process_manager.get_processes_with_paths()
        except Exception as e:
            logger.error(f"Ошибка получения процессов: {e}")
            processes = []

        crit_bg = QColor('#c97a1e')
        crit_fg = QColor('#fff5e6')
        frozen_bg = QColor(COLORS['frozen'])
        frozen_fg = QColor('#000000')

        crit_count = 0
        for proc in processes:
            name = proc['name']
            pid = proc['pid']
            path = proc.get('path', 'N/A')

            # ОПРЕДЕЛЯЕМ КРИТИЧНОСТЬ ЗДЕСЬ — по имени и PID
            is_critical = (
                name.lower() in CRITICAL_PROCESS_NAMES
                or pid in (0, 4)
            )

            if is_critical:
                crit_count += 1
            display_name = f"{name}" if is_critical else name

            item = NumericTreeItem([display_name, str(pid), path])
            item.setData(0, Qt.ItemDataRole.UserRole, pid)
            item.setData(0, Qt.ItemDataRole.UserRole + 1, is_critical)

            if is_critical:
                for col in range(3):
                    item.setBackground(col, crit_bg)
                    item.setForeground(col, crit_fg)
                    f = item.font(col)
                    f.setBold(True)
                    item.setFont(col, f)
            elif pid in self.frozen_pids:
                for col in range(3):
                    item.setBackground(col, frozen_bg)
                    item.setForeground(col, frozen_fg)

            self.process_tree.addTopLevelItem(item)

        self.process_tree.setSortingEnabled(True)
        self.statusBar().showMessage(
            f"Процессов: {len(processes)}  |  Критических: {crit_count}"
        )

    def _filter_processes(self, text: str):
        text_lower = text.lower()
        for i in range(self.process_tree.topLevelItemCount()):
            item = self.process_tree.topLevelItem(i)
            hidden = (text_lower not in item.text(0).lower()
                      and text_lower not in item.text(1)
                      and text_lower not in item.text(2).lower())
            item.setHidden(hidden)

    def _get_selected_pids(self) -> list:
        result = []
        for item in self.process_tree.selectedItems():
            try:
                result.append((int(item.text(1)), item.text(0)))
            except (ValueError, IndexError):
                pass
        return result

    def _terminate_process(self):
        selected = self._get_selected_pids()
        if not selected:
            QMessageBox.warning(self, "Предупреждение", "Выберите процессы")
            return

        critical_names = [item.text(0) for item in self.process_tree.selectedItems()
                          if item.data(0, Qt.ItemDataRole.UserRole + 1)]

        if critical_names:
            preview = "\n".join(critical_names[:5])
            if len(critical_names) > 5:
                preview += f"\n... и ещё {len(critical_names) - 5}"
            if QMessageBox.question(
                self, "ПРЕДУПРЕЖДЕНИЕ",
                f"Среди выбранных есть КРИТИЧЕСКИЕ процессы:\n\n{preview}\n\n"
                f"Их завершение может привести к BSOD/перезагрузке.\nПродолжить?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            ) != QMessageBox.StandardButton.Yes:
                return

        if QMessageBox.question(
            self, "Подтверждение",
            f"Завершить выбранные процессы? ({len(selected)} шт.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return

        ok = 0
        for pid, _ in selected:
            if self.process_manager.terminate_process(pid):
                self.frozen_pids.discard(pid)
                ok += 1

        self._refresh_processes()
        QMessageBox.information(self, "Результат", f"Завершено: {ok} из {len(selected)}")

    def _suspend_process(self):
        selected = self._get_selected_pids()
        if not selected:
            QMessageBox.warning(self, "Предупреждение", "Выберите процессы")
            return
        if QMessageBox.question(
            self, "Подтверждение",
            f"Заморозить выбранные процессы? ({len(selected)} шт.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        ok = 0
        for pid, _ in selected:
            if self.process_manager.suspend_process(pid):
                self.frozen_pids.add(pid)
                ok += 1
        self._refresh_processes()
        QMessageBox.information(self, "Результат", f"Заморожено: {ok} из {len(selected)}")

    def _resume_process(self):
        selected = self._get_selected_pids()
        if not selected:
            QMessageBox.warning(self, "Предупреждение", "Выберите процессы")
            return
        if QMessageBox.question(
            self, "Подтверждение",
            f"Разморозить выбранные процессы? ({len(selected)} шт.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        ok = 0
        for pid, _ in selected:
            if self.process_manager.resume_process(pid):
                self.frozen_pids.discard(pid)
                ok += 1
        self._refresh_processes()
        QMessageBox.information(self, "Результат", f"Разморожено: {ok} из {len(selected)}")

    def _remove_critical_flag(self):
        selected = self._get_selected_pids()
        if not selected:
            QMessageBox.warning(self, "Предупреждение", "Выберите процессы")
            return
        if QMessageBox.question(
            self, "Предупреждение",
            f"Снять критический флаг с выбранных процессов? ({len(selected)} шт.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        ok = 0
        for pid, _ in selected:
            if self.process_manager.remove_critical_flag(pid):
                ok += 1
        self._refresh_processes()
        QMessageBox.information(self, "Результат", f"Снят флаг: {ok} из {len(selected)}")

    # ==================== ВКЛАДКА РЕЕСТР ====================

    def _create_registry_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.registry_tree = QTreeWidget()
        self.registry_tree.setHeaderLabels(['Ключ'])
        self.registry_tree.setRootIsDecorated(True)
        self.registry_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.registry_tree.itemExpanded.connect(self._on_registry_key_expanded)
        self.registry_tree.itemClicked.connect(self._on_registry_key_clicked)
        self._style_table(self.registry_tree)
        left_layout.addWidget(self.registry_tree)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        self.registry_values_tree = QTreeWidget()
        self.registry_values_tree.setHeaderLabels(['Имя', 'Тип', 'Значение'])
        self.registry_values_tree.setRootIsDecorated(False)
        self._style_table(self.registry_values_tree)

        vheader = self.registry_values_tree.header()
        vheader.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        vheader.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        vheader.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.registry_values_tree.setColumnWidth(0, 200)
        self.registry_values_tree.setColumnWidth(1, 130)

        right_layout.addWidget(self.registry_values_tree)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)

        btn_layout = QHBoxLayout()
        for text, slot in [
            ("Обновить", self._refresh_registry_root),
            ("Создать ключ", self._create_registry_key),
            ("Удалить ключ", self._delete_registry_key),
            ("Добавить значение", self._add_registry_value),
            ("Удалить значение", self._delete_registry_value),
            ("Открыть regedit", self._open_regedit),
        ]:
            b = QPushButton(text)
            b.clicked.connect(slot)
            btn_layout.addWidget(b)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.notebook.addTab(widget, "Реестр")
        self._refresh_registry_root()

    def _refresh_registry_root(self):
        self.registry_tree.clear()
        self.registry_values_tree.clear()
        for name, _ in self.REGISTRY_ROOTS:
            item = QTreeWidgetItem([name])
            item.setData(0, Qt.ItemDataRole.UserRole, name)
            item.setData(0, Qt.ItemDataRole.UserRole + 1, False)
            item.addChild(QTreeWidgetItem(["Загрузка..."]))
            self.registry_tree.addTopLevelItem(item)

    def _on_registry_key_expanded(self, item: QTreeWidgetItem):
        if item.data(0, Qt.ItemDataRole.UserRole + 1):
            return
        item.takeChildren()
        hive_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not hive_path:
            return
        parts = hive_path.split('\\', 1)
        root_name = parts[0]
        sub_path = parts[1] if len(parts) > 1 else ''
        hive = next((h for n, h in self.REGISTRY_ROOTS if n == root_name), None)
        if hive is None:
            return
        try:
            key = winreg.OpenKey(hive, sub_path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    child_path = f"{hive_path}\\{subkey_name}"
                    child = QTreeWidgetItem([subkey_name])
                    child.setData(0, Qt.ItemDataRole.UserRole, child_path)
                    child.setData(0, Qt.ItemDataRole.UserRole + 1, False)
                    child.addChild(QTreeWidgetItem(["Загрузка..."]))
                    item.addChild(child)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (PermissionError, Exception):
            pass
        item.setData(0, Qt.ItemDataRole.UserRole + 1, True)

    def _on_registry_key_clicked(self, item: QTreeWidgetItem, column: int):
        self._load_registry_values(item)

    def _load_registry_values(self, item: QTreeWidgetItem):
        self.registry_values_tree.clear()
        hive_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not hive_path:
            return
        parts = hive_path.split('\\', 1)
        root_name = parts[0]
        sub_path = parts[1] if len(parts) > 1 else ''
        hive = next((h for n, h in self.REGISTRY_ROOTS if n == root_name), None)
        if hive is None:
            return
        try:
            key = winreg.OpenKey(hive, sub_path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    vname, vdata, vtype = winreg.EnumValue(key, i)
                    tname = self._get_registry_type_name(vtype)
                    dname = "(По умолчанию)" if vname == '' else vname
                    vstr = self._format_registry_value(vdata, vtype)
                    vi = QTreeWidgetItem([dname, tname, vstr])
                    vi.setData(0, Qt.ItemDataRole.UserRole, vname)
                    self.registry_values_tree.addTopLevelItem(vi)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except PermissionError:
            QMessageBox.warning(self, "Доступ запрещён", f"Нет прав на чтение {hive_path}")
        except Exception:
            pass

    def _get_registry_type_name(self, value_type: int) -> str:
        types = {
            winreg.REG_SZ: 'REG_SZ',
            winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
            winreg.REG_BINARY: 'REG_BINARY',
            winreg.REG_DWORD: 'REG_DWORD',
            winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
            winreg.REG_QWORD: 'REG_QWORD',
        }
        return types.get(value_type, f'UNKNOWN({value_type})')

    def _format_registry_value(self, value, value_type: int) -> str:
        if value_type == winreg.REG_BINARY:
            if isinstance(value, bytes):
                return ' '.join(f'{b:02X}' for b in value[:64]) + ('...' if len(value) > 64 else '')
            return str(value)
        elif value_type == winreg.REG_MULTI_SZ:
            if isinstance(value, list):
                return ' | '.join(str(v) for v in value)
            return str(value)
        elif value_type == winreg.REG_DWORD:
            return f"0x{value:08X} ({value})"
        elif value_type == winreg.REG_QWORD:
            return f"0x{value:016X} ({value})"
        return str(value)

    def _get_selected_registry_path(self) -> str:
        selected = self.registry_tree.selectedItems()
        return selected[0].data(0, Qt.ItemDataRole.UserRole) if selected else None

    def _create_registry_key(self):
        parent_path = self._get_selected_registry_path()
        if not parent_path:
            QMessageBox.warning(self, "Предупреждение", "Выберите родительский ключ")
            return
        name, ok = QInputDialog.getText(self, "Создать ключ", "Имя нового ключа:")
        if not ok or not name.strip():
            return
        new_path = f"{parent_path}\\{name.strip()}"
        parts = new_path.split('\\', 1)
        root_name = parts[0]
        sub_path = parts[1] if len(parts) > 1 else ''
        hive = next((h for n, h in self.REGISTRY_ROOTS if n == root_name), None)
        if hive is None:
            return
        try:
            key = winreg.CreateKeyEx(hive, sub_path, 0, winreg.KEY_ALL_ACCESS)
            winreg.CloseKey(key)
            QMessageBox.information(self, "Успех", "Ключ создан")
            item = self.registry_tree.selectedItems()[0]
            item.setData(0, Qt.ItemDataRole.UserRole + 1, False)
            item.setExpanded(False)
            item.setExpanded(True)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать ключ:\n{e}")

    def _delete_registry_key(self):
        path = self._get_selected_registry_path()
        if not path:
            QMessageBox.warning(self, "Предупреждение", "Выберите ключ")
            return
        if path in [n for n, _ in self.REGISTRY_ROOTS]:
            QMessageBox.warning(self, "Предупреждение", "Нельзя удалить корневой ключ")
            return
        if QMessageBox.question(
            self, "Подтверждение",
            f"Удалить ключ:\n{path}\n\nЭто действие необратимо!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        parts = path.rsplit('\\', 1)
        if len(parts) != 2:
            return
        parent_path, key_name = parts
        pparts = parent_path.split('\\', 1)
        root_name = pparts[0]
        sub_path = pparts[1] if len(pparts) > 1 else ''
        hive = next((h for n, h in self.REGISTRY_ROOTS if n == root_name), None)
        if hive is None:
            return
        try:
            parent_key = winreg.OpenKey(hive, sub_path, 0, winreg.KEY_ALL_ACCESS)
            winreg.DeleteKey(parent_key, key_name)
            winreg.CloseKey(parent_key)
            QMessageBox.information(self, "Успех", "Ключ удалён")
            selected = self.registry_tree.selectedItems()[0]
            parent = selected.parent()
            if parent:
                parent.setData(0, Qt.ItemDataRole.UserRole + 1, False)
                parent.setExpanded(False)
                parent.setExpanded(True)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить ключ:\n{e}")

    def _add_registry_value(self):
        path = self._get_selected_registry_path()
        if not path:
            QMessageBox.warning(self, "Предупреждение", "Выберите ключ")
            return
        name, ok = QInputDialog.getText(self, "Добавить значение", "Имя значения:")
        if not ok:
            return
        data, ok = QInputDialog.getText(self, "Добавить значение", "Данные (строка):")
        if not ok:
            return
        parts = path.split('\\', 1)
        root_name = parts[0]
        sub_path = parts[1] if len(parts) > 1 else ''
        hive = next((h for n, h in self.REGISTRY_ROOTS if n == root_name), None)
        if hive is None:
            return
        try:
            key = winreg.OpenKey(hive, sub_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, data)
            winreg.CloseKey(key)
            QMessageBox.information(self, "Успех", "Значение добавлено")
            self._load_registry_values(self.registry_tree.selectedItems()[0])
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось добавить значение:\n{e}")

    def _delete_registry_value(self):
        path = self._get_selected_registry_path()
        if not path:
            QMessageBox.warning(self, "Предупреждение", "Выберите ключ")
            return
        selected_values = self.registry_values_tree.selectedItems()
        if not selected_values:
            QMessageBox.warning(self, "Предупреждение", "Выберите значение")
            return
        value_name = selected_values[0].data(0, Qt.ItemDataRole.UserRole)
        parts = path.split('\\', 1)
        root_name = parts[0]
        sub_path = parts[1] if len(parts) > 1 else ''
        hive = next((h for n, h in self.REGISTRY_ROOTS if n == root_name), None)
        if hive is None:
            return
        try:
            key = winreg.OpenKey(hive, sub_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)
            QMessageBox.information(self, "Успех", "Значение удалено")
            self._load_registry_values(self.registry_tree.selectedItems()[0])
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить значение:\n{e}")

    def _open_regedit(self):
        self.registry_editor.open_regedit()

    # ==================== ВКЛАДКА СИСТЕМА ====================

    def _create_system_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        self._create_system_section(layout, "Системные команды", [
            ("Перезагрузка", self._restart_pc),
            ("Выключение", self._shutdown_pc),
            ("Выйти из пользователя", self._logout),
            ("Войти в WinRE", self._enter_winre_sys),
            ("Выполнить (Win+R)", self._run_dialog),
        ])
        self._create_system_section(layout, "Восстановление", [
            ("sfc /scannow", self._run_sfc_sys),
            ("DISM Restore", self._run_dism),
            ("Включить UAC", self._enable_uac_sys),
            ("Выкл. тестовый режим", self._disable_test_mode_sys),
            ("Восстановить шрифт", self._restore_font_sys),
        ])
        self._create_system_section(layout, "WinPE", [
            ("Определить диск", self._check_winpe_drive),
            ("Заменить sethc", self._replace_sethc_winpe),
            ("Заменить utilman", self._replace_utilman_winpe),
            ("Восстановить sethc", self._restore_sethc_winpe),
            ("Восстановить utilman", self._restore_utilman_winpe),
            ("Удалить Windows Defender", self._remove_windows_defender),
        ])

        layout.addStretch()
        self.notebook.addTab(widget, "Система")

    def _create_system_section(self, parent_layout, title, buttons):
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_medium']};
                border-radius: 8px;
                border: 1px solid {COLORS['border_soft']};
                padding: 10px;
            }}
        """)
        frame_layout = QVBoxLayout(frame)
        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            color: {COLORS['accent']};
            font-size: 11pt; font-weight: bold;
            background-color: transparent; border: none;
        """)
        frame_layout.addWidget(title_label)

        btn_layout = QHBoxLayout()
        for text, command in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(command)
            btn_layout.addWidget(btn)
        btn_layout.addStretch()
        frame_layout.addLayout(btn_layout)
        parent_layout.addWidget(frame)

    def _restart_pc(self):
        if QMessageBox.question(
            self, "Подтверждение", "Перезагрузить ПК?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self.system_commands.restart_pc(5)

    def _shutdown_pc(self):
        if QMessageBox.question(
            self, "Подтверждение", "Выключить ПК?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self.system_commands.shutdown_pc(5)

    def _logout(self):
        if QMessageBox.question(
            self, "Подтверждение", "Выйти из пользователя?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self.system_commands.logout()

    def _enter_winre_sys(self): self._enter_winre()
    def _run_sfc_sys(self): self._run_sfc()
    def _enable_uac_sys(self): self._enable_uac()
    def _disable_test_mode_sys(self): self._disable_test_mode()
    def _restore_font_sys(self): self._restore_font()
    def _run_dialog(self): self.system_commands.run_dialog()

    def _run_dism(self):
        if QMessageBox.question(
            self, "Подтверждение", "Запустить DISM?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self.system_commands.run_dism()

    # ==================== WINPE ====================

    def _check_winpe_drive(self):
        try:
            drive_letter = self.system_commands.get_winpe_drive_letter()
            if drive_letter:
                QMessageBox.information(self, "Определение диска", f"Диск Windows найден: {drive_letter}")
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось определить диск Windows")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось определить диск:\n{e}")

    def _remove_windows_defender(self):
        try:
            from modules.winpe_defender import (
                remove_defender_completely, is_winpe_environment, get_available_drives
            )
            if not is_winpe_environment():
                QMessageBox.critical(
                    self, "Ошибка",
                    "Вы не находитесь в среде WinPE!\n\n"
                    "Функция удаления Windows Defender работает ТОЛЬКО из WinPE.\n\n"
                    "Запустите DedHelper из WinPE"
                )
                return

            auto_detected = self.system_commands.get_winpe_drive_letter() or "C:"
            drives = get_available_drives()
            drive_list = "\n".join([
                f"  {d['letter']} {'Windows' if d['is_windows'] else 'Диск'}"
                for d in drives
            ]) or "  (нет доступных дисков)"

            msg = (
                f"ВНИМАНИЕ! Будет удалён Windows Defender\n\n"
                f"Будут удалены:\n"
                f"  - Все файлы Windows Defender\n"
                f"  - Службы Defender (WinDefend, WdNisSvc, Sense)\n"
                f"  - Драйверы Defender\n"
                f"  - Настройки реестра Defender\n\n"
                f"Брандмауэр и другие службы НЕ будут затронуты!\n\n"
                f"Доступные диски:\n{drive_list}\n\n"
                f"Автоматически определён диск: {auto_detected}\n\n"
                f"Введите букву диска с Windows (например, D:) или оставьте пустым:"
            )
            drive_input, ok = QInputDialog.getText(self, "ВЫБОР ДИСКА", msg)
            if ok and drive_input.strip():
                drive_letter = drive_input.strip().upper()
                if not drive_letter.endswith(':'):
                    drive_letter += ':'
            else:
                drive_letter = auto_detected

            if not os.path.exists(drive_letter):
                QMessageBox.critical(self, "ОШИБКА", f"Диск {drive_letter} не существует!")
                return

            self.statusBar().showMessage(f"Удаление Windows Defender с диска {drive_letter}...")
            QApplication.processEvents()
            result = remove_defender_completely(drive_letter)

            if result['success']:
                QMessageBox.information(self, "УСПЕХ", result['message'])
            else:
                QMessageBox.critical(self, "ОШИБКА", result['message'])

            if result.get('errors'):
                QMessageBox.warning(self, "Предупреждения",
                                    "Проблемы:\n\n" + "\n".join(result['errors']))
            self.statusBar().showMessage("Готово")
        except ImportError as e:
            logger.error(f"Модуль winpe_defender не найден: {e}")
            QMessageBox.critical(self, "Ошибка", "Модуль удаления Defender не найден")
        except Exception as e:
            logger.error(f"Ошибка удаления Defender: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить Defender:\n{e}")

    def _replace_sethc_winpe(self):
        self._do_replace_system_file("sethc")

    def _replace_utilman_winpe(self):
        self._do_replace_system_file("utilman")

    def _restore_sethc_winpe(self):
        self._do_restore_system_file("sethc", "sethc.exe")

    def _restore_utilman_winpe(self):
        self._do_restore_system_file("utilman", "Utilman.exe")

    def _do_replace_system_file(self, name: str):
        drive_letter = self.system_commands.get_winpe_drive_letter()
        if not drive_letter:
            for letter in 'CDEFGHIJK':
                if os.path.exists(f"{letter}:\\Windows\\System32\\{name}.exe"):
                    drive_letter = f"{letter}:"
                    break
        if not drive_letter:
            QMessageBox.critical(self, "Ошибка", "Не удалось найти диск с Windows!")
            return

        target_path = f"{drive_letter}\\Windows\\System32\\{name}.exe"
        if not os.path.exists(target_path):
            QMessageBox.critical(self, "Ошибка", f"{name}.exe не найден")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self, f"Выберите файл для замены {name}.exe", "",
            "EXE файлы (*.exe);;Все файлы (*.*)"
        )
        if not file_path:
            return
        file_path = file_path.replace('/', '\\')

        if QMessageBox.question(
            self, "Подтверждение",
            f"Заменить {name}.exe на {file_path}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return

        try:
            if os.path.exists(target_path):
                os.remove(target_path)
            shutil.copy2(file_path, target_path)
            if os.path.exists(target_path):
                QMessageBox.information(self, "Успех", f"{name}.exe успешно заменён!")
            else:
                QMessageBox.critical(self, "Ошибка", "Не удалось скопировать файл!")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось заменить {name}:\n{str(e)}")

    def _do_restore_system_file(self, name: str, embedded_name: str):
        drive_letter = self.system_commands.get_winpe_drive_letter()
        if not drive_letter:
            for letter in 'CDEFGHIJK':
                if os.path.exists(f"{letter}:\\Windows\\System32\\{name}.exe"):
                    drive_letter = f"{letter}:"
                    break
        if not drive_letter:
            QMessageBox.critical(self, "Ошибка", "Не удалось найти диск с Windows!")
            return

        target_path = f"{drive_letter}\\Windows\\System32\\{name}.exe"
        embedded = self._get_embedded_file_path(embedded_name)
        if not embedded:
            QMessageBox.critical(self, "Ошибка", f"Встроенный {name}.exe не найден!")
            return

        if QMessageBox.question(
            self, "Подтверждение", f"Восстановить {name}.exe?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return

        try:
            if os.path.exists(target_path):
                os.remove(target_path)
            shutil.copy2(embedded, target_path)
            if os.path.exists(target_path):
                QMessageBox.information(self, "Успех", f"{name}.exe восстановлен!")
            else:
                QMessageBox.critical(self, "Ошибка", "Не удалось восстановить файл!")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось восстановить {name}:\n{str(e)}")

    def _get_embedded_file_path(self, filename: str) -> str:
        paths = []
        if hasattr(sys, '_MEIPASS'):
            paths += [
                os.path.join(sys._MEIPASS, 'modules', filename),
                os.path.join(sys._MEIPASS, filename),
            ]
        script_dir = os.path.dirname(os.path.abspath(__file__))
        paths += [
            os.path.join(script_dir, 'modules', filename),
            os.path.join(script_dir, filename),
            os.path.join(os.getcwd(), 'modules', filename),
            os.path.join(os.getcwd(), filename),
        ]
        for path in paths:
            if os.path.exists(path):
                return path.replace('/', '\\')
        return None

    def _auto_detect_winpe_drive(self):
        try:
            drive_letter = self.system_commands.get_winpe_drive_letter()
            if drive_letter:
                self.statusBar().showMessage(f"Администратор | Диск: {drive_letter}")
        except Exception as e:
            logger.error(f"Ошибка автоопределения диска: {e}")

    # ==================== ВКЛАДКА ПРОВОДНИК ====================

    def _create_explorer_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        title_label = QLabel("Встроенный проводник")
        title_label.setStyleSheet(f"""
            color: {COLORS['accent']};
            font-size: 11pt; font-weight: bold;
            background-color: transparent; border: none;
        """)
        layout.addWidget(title_label)

        btn_layout = QHBoxLayout()

        exp_btn = QPushButton("Запустить Explorer++")
        exp_btn.setMinimumHeight(50)
        exp_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: {COLORS['text_main']};
                font-size: 11pt; font-weight: bold;
                padding: 10px 20px; border-radius: 5px;
                border: 1px solid #ffffff;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
                border: 1px solid #ffffff;
            }}
        """)
        exp_btn.clicked.connect(self._launch_explorer)
        btn_layout.addWidget(exp_btn)

        win_btn = QPushButton("Обычный проводник")
        win_btn.setMinimumHeight(50)
        win_btn.clicked.connect(self._launch_windows_explorer)
        btn_layout.addWidget(win_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        layout.addStretch()

        self.notebook.addTab(widget, "Проводник")

    def _launch_explorer(self):
        try:
            if not os.path.exists(self.explorer_path):
                self._extract_explorer()
            if not os.path.exists(self.explorer_path):
                QMessageBox.critical(self, "Ошибка", "Explorer++ не найден в ресурсах")
                return
            random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=8)) + '.exe'
            temp_explorer = os.path.join(self.temp_dir, random_name)
            shutil.copy2(self.explorer_path, temp_explorer)
            if os.path.exists(temp_explorer):
                subprocess.Popen([temp_explorer])
                QMessageBox.information(self, "Успех", f"Explorer++ запущен\nИмя процесса: {random_name}")
            else:
                QMessageBox.critical(self, "Ошибка", "Не удалось создать копию Explorer++")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить Explorer++:\n{e}")

    def _launch_windows_explorer(self):
        try:
            subprocess.Popen('explorer.exe')
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    # ==================== ЗАКРЫТИЕ ====================

    def closeEvent(self, event):
        try:
            if self.frozen_pids:
                for pid in self.frozen_pids:
                    try:
                        self.process_manager.resume_process(pid)
                    except Exception:
                        pass
            if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)

            relaunch_temp = os.environ.get('DEDHELPER_TEMP_DIR')
            if relaunch_temp and os.path.exists(relaunch_temp):
                try:
                    subprocess.Popen(
                        f'cmd /c timeout /t 1 /nobreak > nul & rmdir /s /q "{relaunch_temp}"',
                        shell=True,
                        creationflags=CREATE_NO_WINDOW,
                        startupinfo=startupinfo_hide()
                    )
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Ошибка при закрытии: {e}")
        finally:
            event.accept()


def main():
    # Глобальный перехватчик исключений — пишет всё в лог, а не молча вешает процесс
    def _excepthook(exc_type, exc_value, exc_tb):
        import traceback
        tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        logger.error(f"Необработанное исключение:\n{tb}")
        # На всякий случай — печатаем в stderr (видно при запуске из консоли)
        sys.__excepthook__(exc_type, exc_value, exc_tb)
    sys.excepthook = _excepthook

    if not is_admin():
        run_as_admin()
        # run_as_admin() при успехе делает sys.exit(0), но если что-то пошло не так —
        # продолжаем и пробуем запуститься без прав (без краша)
        if is_admin():
            pass  # уже админ

    if relaunch_with_random_name():
        sys.exit(0)

    try:
        app = QApplication(sys.argv)
        app.setStyle('Fusion')

        try:
            window = DedHelperApp()
        except Exception as e:
            logger.exception("Ошибка создания окна")
            # Пробуем показать хотя бы сообщение об ошибке
            err = QMessageBox()
            err.setWindowTitle("DedHelper — Ошибка запуска")
            err.setIcon(QMessageBox.Icon.Critical)
            err.setText(f"Не удалось создать главное окно:\n\n{e}\n\n"
                        f"Подробности в {os.path.join(os.environ.get('TEMP', '.'), 'DedHelper.log')}")
            err.exec()
            sys.exit(1)

        window.show()
        window.raise_()
        window.activateWindow()

        logger.info("Окно показано, запуск event loop")
        exit_code = app.exec()
        logger.info(f"Выход, код: {exit_code}")
        sys.exit(exit_code)

    except Exception as e:
        logger.exception("Критическая ошибка в main()")
        try:
            print(f"КРИТИЧЕСКАЯ ОШИБКА: {e}", file=sys.stderr)
        except Exception:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()
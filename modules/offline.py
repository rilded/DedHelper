"""
Офлайн-сессия: работа с установленной Windows из WinPE.

В WinPE всё по умолчанию смотрит в X: (RAM-диск). Чтобы работать с реальной
системой, нужно:
  1) найти её диск (не X:) — есть <drive>:\\Windows\\System32\\config\\SOFTWARE и SYSTEM
  2) загрузить хайвы через `reg load HKLM\\OFFLINE_<NAME> <drive>:\\Windows\\System32\\config\\<NAME>`
  3) для каждого пользователя загрузить NTUSER.DAT (иначе HKCU смотрит в X:)
  4) разворачивать `CurrentControlSet` -> `ControlSet00N` из `Select\\Current`
  5) файлы читать по пути `<drive>:\\Windows\\...`
"""
import os
import re
import subprocess
import logging
import winreg

logger = logging.getLogger(__name__)
CREATE_NO_WINDOW = 0x08000000


class OfflineSession:
    active = False
    drive = ""              # 'C:'
    hives = {}              # {'SOFTWARE': 'OFFLINE_SOFTWARE', ...}
    ntuser_users = []       # ['Admin', 'User'] — загруженные NTUSER

    # ---------- определение окружения ----------
    @classmethod
    def is_winpe(cls) -> bool:
        sys_drive = (os.environ.get("SystemDrive") or "").rstrip(":").upper()
        if sys_drive == "X":
            return True
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\MiniNT"):
                return True
        except OSError:
            pass
        return False

    # ---------- запуск / остановка ----------
    @classmethod
    def start(cls):
        if cls.active:
            return
        if not cls.is_winpe():
            return
        drive = cls._find_windows_drive()
        if not drive:
            logger.error("Офлайн: диск Windows не найден")
            return
        cls.drive = drive
        cls.hives = cls._load_hives(drive)
        if "SOFTWARE" not in cls.hives or "SYSTEM" not in cls.hives:
            logger.warning("Офлайн: основные хайвы не загружены — работаем с X:")
        cls.ntuser_users = cls._load_all_ntusers(drive)
        cls.active = True
        logger.info(f"Офлайн активен. Диск: {drive}, хайвы: {list(cls.hives)}, "
                    f"пользователи: {cls.ntuser_users}")

    @classmethod
    def stop(cls):
        for hive in list(cls.hives.values()):
            cls._reg_unload(hive)
        for user in cls.ntuser_users:
            cls._reg_unload(f"OFFLINE_NTUSER_{user}")
        cls.active = False
        cls.drive = ""
        cls.hives = {}
        cls.ntuser_users = []

    # ---------- внутренние утилиты ----------
    @classmethod
    def _reg(cls, *args):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        return subprocess.run(["reg"] + list(args), capture_output=True,
                              startupinfo=si, creationflags=CREATE_NO_WINDOW)

    @classmethod
    def _reg_unload(cls, mount_name):
        if not mount_name:
            return True
        import time
        for attempt in range(3):
            r = cls._reg("unload", f"HKLM\\{mount_name}")
            if r.returncode == 0:
                return True
            err = r.stderr.decode("cp866", errors="ignore").strip()
            logger.warning(f"reg unload {mount_name} (попытка {attempt+1}): {err}")
            time.sleep(0.5)
        logger.error(f"reg unload {mount_name}: НЕ УДАЛОСЬ выгрузить после 3 попыток — "
                     f"изменения могут не сохраниться на диск!")
        return False

    @classmethod
    def _find_windows_drive(cls) -> str:
        for letter in "CDEFGHIJKLMNOPQRSTUVWY":
            cfg = f"{letter}:\\Windows\\System32\\config"
            if os.path.isfile(os.path.join(cfg, "SOFTWARE")) and \
               os.path.isfile(os.path.join(cfg, "SYSTEM")):
                return f"{letter}:"
        return ""

    @classmethod
    def _load_hives(cls, drive) -> dict:
        cfg = f"{drive}\\Windows\\System32\\config"
        loaded = {}
        for name in ("SOFTWARE", "SYSTEM", "SAM", "SECURITY", "DEFAULT"):
            hive_file = os.path.join(cfg, name)
            if not os.path.isfile(hive_file):
                continue
            mount = f"OFFLINE_{name}"
            cls._reg_unload(mount)
            r = cls._reg("load", f"HKLM\\{mount}", hive_file)
            if r.returncode == 0:
                loaded[name] = mount
            else:
                err = r.stderr.decode("cp866", errors="ignore").strip()
                logger.error(f"Офлайн: не загружен {name}: {err}")
        return loaded

    @classmethod
    def _load_all_ntusers(cls, drive) -> list:
        users_dir = f"{drive}\\Users"
        if not os.path.isdir(users_dir):
            return []
        skip = {"Public", "Default", "Default User", "All Users",
                "WDAGUtilityAccount"}
        loaded = []
        for entry in os.listdir(users_dir):
            if entry in skip:
                continue
            ntuser = os.path.join(users_dir, entry, "NTUSER.DAT")
            if not os.path.isfile(ntuser):
                continue
            mount = f"OFFLINE_NTUSER_{entry}"
            cls._reg_unload(mount)
            r = cls._reg("load", f"HKLM\\{mount}", ntuser)
            if r.returncode == 0:
                loaded.append(entry)
        return loaded

    # ---------- развёртывание путей реестра ----------
    @classmethod
    def _current_control_set(cls) -> str:
        try:
            sys_mount = cls.hives.get("SYSTEM")
            if not sys_mount:
                return "ControlSet001"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                f"{sys_mount}\\Select", 0, winreg.KEY_READ) as k:
                val, _ = winreg.QueryValueEx(k, "Current")
                return f"ControlSet{val:03d}"
        except OSError:
            return "ControlSet001"

    @classmethod
    def expand_hklm_path(cls, subkey_path: str) -> str:
        """SOFTWARE\\... -> OFFLINE_SOFTWARE\\...; SYSTEM\\CCS\\... -> OFFLINE_SYSTEM\\CS00N\\..."""
        if not cls.active or not subkey_path:
            return subkey_path
        parts = subkey_path.split("\\", 1)
        top = parts[0].upper()
        rest = parts[1] if len(parts) > 1 else ""
        if top not in cls.hives:
            return subkey_path
        mount = cls.hives[top]
        if top == "SYSTEM" and rest.upper().startswith("CURRENTCONTROLSET"):
            cs = cls._current_control_set()
            rest = cs + rest[len("CurrentControlSet"):]
        return f"{mount}\\{rest}" if rest else mount

    # ---------- открытие ключей ----------
    @classmethod
    def open_hklm(cls, subkey_path: str, access: int = winreg.KEY_READ):
        path = cls.expand_hklm_path(subkey_path) if cls.active else subkey_path
        return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, access)

    @classmethod
    def create_hklm(cls, subkey_path: str,
                    access: int = winreg.KEY_SET_VALUE | winreg.KEY_READ):
        path = cls.expand_hklm_path(subkey_path) if cls.active else subkey_path
        return winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, access)

    @classmethod
    def open_hkcr(cls, subpath: str, access: int = winreg.KEY_READ):
        if cls.active:
            base = f"{cls.hives.get('SOFTWARE', 'SOFTWARE')}\\Classes"
            full = f"{base}\\{subpath}" if subpath else base
            return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, full, 0, access)
        return winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, subpath, 0, access)

    @classmethod
    def create_hkcr(cls, subpath: str,
                    access: int = winreg.KEY_SET_VALUE | winreg.KEY_READ):
        if cls.active:
            base = f"{cls.hives.get('SOFTWARE', 'SOFTWARE')}\\Classes"
            full = f"{base}\\{subpath}" if subpath else base
            return winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, full, 0, access)
        return winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, subpath, 0, access)

    @classmethod
    def hkcu_roots(cls) -> list:
        """[(label, hkey, prefix)] для итерации по HKCU всех пользователей."""
        if not cls.active:
            return [("HKCU", winreg.HKEY_CURRENT_USER, "")]
        return [(f"HKCU ({u})", winreg.HKEY_LOCAL_MACHINE, f"OFFLINE_NTUSER_{u}")
                for u in cls.ntuser_users]

    @classmethod
    def first_loaded_user(cls) -> str:
        return cls.ntuser_users[0] if cls.ntuser_users else ""

    @classmethod
    def open_hkcu(cls, subpath: str, access: int = winreg.KEY_READ,
                  user: str = ""):
        if not cls.active:
            return winreg.OpenKey(winreg.HKEY_CURRENT_USER, subpath, 0, access)
        u = user or cls.first_loaded_user()
        if not u:
            raise FileNotFoundError("No NTUSER loaded")
        full = f"OFFLINE_NTUSER_{u}\\{subpath}" if subpath else f"OFFLINE_NTUSER_{u}"
        return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, full, 0, access)

    @classmethod
    def create_hkcu(cls, subpath: str,
                    access: int = winreg.KEY_SET_VALUE | winreg.KEY_READ,
                    user: str = ""):
        if not cls.active:
            return winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, subpath, 0, access)
        u = user or cls.first_loaded_user()
        if not u:
            raise FileNotFoundError("No NTUSER loaded")
        full = f"OFFLINE_NTUSER_{u}\\{subpath}" if subpath else f"OFFLINE_NTUSER_{u}"
        return winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, full, 0, access)

    # ---------- файловые пути ----------
    @classmethod
    def windows(cls, *parts) -> str:
        if cls.active:
            base = f"{cls.drive}\\Windows"
        else:
            base = os.environ.get("SystemRoot", r"C:\Windows")
        return os.path.join(base, *parts) if parts else base

    @classmethod
    def system32(cls, *parts) -> str:
        return os.path.join(cls.windows("System32"), *parts) if parts \
            else cls.windows("System32")

    @classmethod
    def program_data(cls, *parts) -> str:
        if cls.active:
            base = f"{cls.drive}\\ProgramData"
        else:
            base = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(base, *parts) if parts else base

    @classmethod
    def users_dir(cls) -> str:
        if cls.active:
            return f"{cls.drive}\\Users"
        return os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users")

    @classmethod
    def startup_dirs(cls) -> list:
        """[(label, path)] — папки автозагрузки для всех пользователей."""
        out = []
        sub = os.path.join("Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        if cls.active:
            for user in cls.ntuser_users:
                p = os.path.join(cls.users_dir(), user, "AppData", "Roaming", sub)
                out.append((f"Пользователь: {user}", p))
            out.append(("Все пользователи", os.path.join(cls.program_data(), sub)))
        else:
            appdata = os.environ.get("APPDATA")
            if appdata:
                out.append(("Пользователь", os.path.join(appdata, sub)))
            pd = os.environ.get("ProgramData")
            if pd:
                out.append(("Все пользователи", os.path.join(pd, sub)))
        return out

    # ---------- expandvars ----------
    @classmethod
    def expand_vars(cls, text: str) -> str:
        """Разворачивает %windir%/%SystemRoot%/%SystemDrive% в путь целевой Windows."""
        if not text:
            return text
        if not cls.active:
            return os.path.expandvars(text)
        drive = cls.drive.rstrip(":")
        t = text
        t = re.sub(r'%windir%', cls.windows(), t, flags=re.IGNORECASE)
        t = re.sub(r'%SystemRoot%', cls.windows(), t, flags=re.IGNORECASE)
        t = re.sub(r'%SystemDrive%', drive, t, flags=re.IGNORECASE)
        return os.path.expandvars(t)
# ---------------------------------------------------------------------------
# Модульные обёртки для удобства импорта
# ---------------------------------------------------------------------------

def is_winpe() -> bool:
    """Модульная обёртка над OfflineSession.is_winpe().
    Используется в main.py как `from modules.offline import is_winpe`."""
    return OfflineSession.is_winpe()
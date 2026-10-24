"""
Системные команды (офлайн-aware).

Изменения 7.2:
  * get_winpe_drive_letter -> OfflineSession.drive
  * sethc/utilman — через OfflineSession.system32()
  * UAC / шрифт / LogonUI — через офлайн-хайв
  * restart/shutdown/logout/enter_winre/run_sfc/run_dism — возвращают
    False в офлайне (нет смысла из WinPE)
"""
import subprocess
import ctypes
import os
import shutil
import logging
import random
import string
import winreg

try:
    from .offline import OfflineSession
except (ImportError, ValueError):
    from offline import OfflineSession

CREATE_NO_WINDOW = 0x08000000
logger = logging.getLogger(__name__)


def generate_random_name(length=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def run_hidden_command(cmd, capture_output=False):
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return subprocess.run(cmd, shell=True, capture_output=capture_output,
                          startupinfo=si, creationflags=CREATE_NO_WINDOW)


def run_hidden_powershell(ps_command, capture_output=True, random_name=True):
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    if random_name:
        import tempfile
        temp_dir = tempfile.mkdtemp(prefix='PS_')
        ps_exe = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                              'System32\\WindowsPowerShell\\v1.0\\powershell.exe')
        ps_copy = os.path.join(temp_dir, generate_random_name(12) + '.exe')
        try:
            shutil.copy2(ps_exe, ps_copy)
        except Exception:
            ps_copy = ps_exe
        return subprocess.run(
            [ps_copy, '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
            capture_output=capture_output, startupinfo=si,
            creationflags=CREATE_NO_WINDOW,
        )
    return subprocess.run(
        ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
        capture_output=capture_output, startupinfo=si,
        creationflags=CREATE_NO_WINDOW,
    )


def decode_output(stdout_bytes: bytes) -> str:
    if not stdout_bytes:
        return ""
    for enc in ('utf-8', 'cp1251', 'cp866'):
        try:
            return stdout_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return stdout_bytes.decode('utf-8', errors='replace')


class SystemCommands:

    def __init__(self):
        self.is_admin = ctypes.windll.shell32.IsUserAnAdmin()

    # ---------- офлайн-заглушки ----------
    def _offline_denied(self, action: str) -> bool:
        logger.warning(f"{action}: недоступно из WinPE (офлайн)")
        return False

    # ---------- shutdown / reboot ----------
    def restart_pc(self, timeout=5):
        if OfflineSession.active:
            return self._offline_denied("restart_pc")
        run_hidden_command(f'shutdown /r /t {timeout}')
        return True

    def shutdown_pc(self, timeout=5):
        if OfflineSession.active:
            return self._offline_denied("shutdown_pc")
        run_hidden_command(f'shutdown /s /t {timeout}')
        return True

    def logout(self):
        if OfflineSession.active:
            return self._offline_denied("logout")
        run_hidden_command('shutdown /l')
        return True

    def enter_winre(self):
        if OfflineSession.active:
            return self._offline_denied("enter_winre")
        run_hidden_command('shutdown /r /o /t 0')
        return True

    def run_dialog(self):
        try:
            subprocess.Popen('explorer.exe shell:::{2559a1f8-21d7-11d4-bdaf-00c04f60b9f0}')
            return True
        except Exception:
            return False

    # ---------- UAC / восстановление ----------
    def enable_uac(self) -> bool:
        try:
            key = OfflineSession.open_hklm(
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                winreg.KEY_ALL_ACCESS)
        except OSError as e:
            logger.error(f"enable_uac open: {e}")
            return False
        try:
            winreg.SetValueEx(key, 'EnableLUA', 0, winreg.REG_DWORD, 1)
            try:
                winreg.SetValueEx(key, 'ConsentPromptBehaviorAdmin', 0,
                                  winreg.REG_DWORD, 5)
            except OSError:
                pass
            try:
                winreg.SetValueEx(key, 'PromptOnSecureDesktop', 0,
                                  winreg.REG_DWORD, 1)
            except OSError:
                pass
            return True
        except OSError as e:
            logger.error(f"enable_uac: {e}")
            return False
        finally:
            winreg.CloseKey(key)

    def disable_uac(self) -> bool:
        try:
            key = OfflineSession.open_hklm(
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                winreg.KEY_ALL_ACCESS)
        except OSError:
            return False
        try:
            winreg.SetValueEx(key, 'EnableLUA', 0, winreg.REG_DWORD, 0)
            return True
        finally:
            winreg.CloseKey(key)

    def run_sfc(self):
        if OfflineSession.active:
            return self._offline_denied("run_sfc")
        run_hidden_command('start "SFC Scan" cmd /k "sfc /scannow"')
        return True

    def run_dism(self):
        if OfflineSession.active:
            return self._offline_denied("run_dism")
        run_hidden_command(
            'start "DISM Scan" cmd /k "DISM /Online /Cleanup-Image /RestoreHealth"')
        return True

    def restore_font_default(self) -> bool:
        try:
            key = OfflineSession.open_hklm(
                r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes',
                winreg.KEY_SET_VALUE | winreg.KEY_READ)
        except OSError:
            return False
        try:
            try:
                winreg.DeleteValue(key, 'Segoe UI')
            except OSError:
                pass
            return True
        finally:
            winreg.CloseKey(key)

    def restore_logonui(self) -> bool:
        try:
            key = OfflineSession.open_hklm(
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI',
                winreg.KEY_SET_VALUE | winreg.KEY_READ)
        except OSError:
            return False
        try:
            try:
                winreg.SetValueEx(key, 'LastLogonUID', 0, winreg.REG_DWORD, 1)
            except OSError:
                pass
            return True
        finally:
            winreg.CloseKey(key)

    # ---------- файлы ----------
    def take_ownership(self, filepath):
        try:
            run_hidden_command(f'takeown /f "{filepath}" /a', capture_output=True)
            run_hidden_command(
                f'icacls "{filepath}" /grant Administrators:F', capture_output=True)
            return True
        except Exception:
            return False

    def unlock_file(self, filepath):
        try:
            run_hidden_powershell(f'Unblock-File -Path "{filepath}"')
            return True
        except Exception:
            return False

    # ---------- sethc / utilman ----------
    def replace_sethc(self, target_exe: str) -> bool:
        if not os.path.exists(target_exe):
            return False
        sethc_path = OfflineSession.system32('sethc.exe')
        return self._replace_file_powershell(target_exe, sethc_path)

    def replace_utilman(self, target_exe: str) -> bool:
        if not os.path.exists(target_exe):
            return False
        utilman_path = OfflineSession.system32('utilman.exe')
        return self._replace_file_powershell(target_exe, utilman_path)

    def restore_sethc(self, modules_dir: str = None) -> bool:
        if modules_dir is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            modules_dir = os.path.dirname(script_dir)
        src = os.path.join(modules_dir, 'modules', 'sethc.exe')
        if not os.path.exists(src):
            src = os.path.join(modules_dir, 'sethc.exe')
        if not os.path.exists(src):
            return False
        return self._replace_file_powershell(src, OfflineSession.system32('sethc.exe'))

    def restore_utilman(self, modules_dir: str = None) -> bool:
        if modules_dir is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            modules_dir = os.path.dirname(script_dir)
        src = os.path.join(modules_dir, 'modules', 'Utilman.exe')
        if not os.path.exists(src):
            src = os.path.join(modules_dir, 'Utilman.exe')
        if not os.path.exists(src):
            return False
        return self._replace_file_powershell(src, OfflineSession.system32('utilman.exe'))

    def _replace_file_powershell(self, src, dst) -> bool:
        if OfflineSession.active:
            # офлайн: SYSTEM + файл не заблокирован -> простая замена через os
            try:
                if not os.path.isfile(src):
                    return False
                try:
                    os.chmod(dst, 0o777)
                except OSError:
                    pass
                if os.path.exists(dst):
                    try:
                        os.remove(dst)
                    except OSError:
                        pass
                shutil.copy2(src, dst)
                return True
            except Exception as e:
                logger.error(f"_replace_file (offline): {e}")
                return False
        # online: powershell с ownership
        ps_script = f'''
$ErrorActionPreference = "Stop"
$src = "{src}"
$dst = "{dst}"
if (-not (Test-Path $src)) {{ exit 1 }}
try {{
    $ti = Get-Process TrustedInstaller -ErrorAction SilentlyContinue
    if ($ti) {{ Stop-Process $ti -Force }}
}} catch {{}}
if (Test-Path $dst) {{
    try {{
        $acl = Get-Acl $dst
        $adm = New-Object System.Security.Principal.NTAccount("Administrators")
        $acl.SetOwner($adm)
        Set-Acl $dst -AclObject $acl
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adm, "FullControl", "Allow")
        $acl.ResetAccessRule($rule)
        Set-Acl $dst -AclObject $acl
        [System.IO.File]::SetAttributes($dst, "Normal")
        Remove-Item $dst -Force
    }} catch {{}}
}}
Copy-Item $src $dst -Force
'''
        return run_hidden_powershell(ps_script).returncode == 0

    # ---------- восстановление из WinRE ----------
    def create_restore_point(self, description="VirusBypass Tool"):
        if OfflineSession.active:
            return False
        ps = (f'Enable-ComputerRestore -Drive "C:\\"; '
              f'Checkpoint-Computer -Description "{description}" '
              f'-RestorePointType "MODIFY_SETTINGS"')
        return run_hidden_powershell(ps).returncode == 0

    def run_system_restore(self):
        if OfflineSession.active:
            return False
        run_hidden_command('start "System Restore" rstrui.exe')
        return True

    # ---------- WinPE ----------
    def get_winpe_drive_letter(self):
        if OfflineSession.active:
            return OfflineSession.drive
        try:
            from .winpe_tools import get_windows_drive_letter
            return get_windows_drive_letter()
        except Exception:
            return None

    def replace_sethc_winpe(self, target_exe=None) -> dict:
        from .winpe_tools import replace_sethc_winpe
        return replace_sethc_winpe(target_exe)

    def replace_utilman_winpe(self, target_exe=None) -> dict:
        from .winpe_tools import replace_utilman_winpe
        return replace_utilman_winpe(target_exe)

    def restore_sethc_winpe(self, modules_dir=None) -> dict:
        from .winpe_tools import restore_sethc_winpe
        return restore_sethc_winpe(modules_dir)

    def restore_utilman_winpe(self, modules_dir=None) -> dict:
        from .winpe_tools import restore_utilman_winpe
        return restore_utilman_winpe(modules_dir)

    def check_bitlocker_winpe(self, drive_letter=None) -> dict:
        from .winpe_tools import check_bitlocker_status
        return check_bitlocker_status(drive_letter)

    def list_volumes_winpe(self) -> list:
        from .winpe_tools import list_volumes
        return list_volumes()


def restart_pc(timeout=5):
    return SystemCommands().restart_pc(timeout)


def enter_winre():
    return SystemCommands().enter_winre()


def run_sfc():
    return SystemCommands().run_sfc()
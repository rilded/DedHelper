"""
DedHelper - Модули
Утилита для восстановления Windows после заражения вирусами
"""

from .autorun import AutorunManager, get_all_autoruns, remove_autorun
from .restrictions import RestrictionsManager, get_restrictions, remove_all_restrictions
from .system import SystemCommands, restart_pc, enter_winre, run_sfc, disable_test_mode
from .recovery import WinREManager, get_winre_status, enable_winre, disable_winre, boot_to_winre
from .processes import ProcessManager, get_processes, terminate_process, suspend_process, resume_process
from .registry import RegistryEditor, read_registry, write_registry, delete_registry, open_regedit
from .winpe_defender import remove_defender_completely, find_windows_drive

__all__ = [
    # Autorun
    'AutorunManager',
    'get_all_autoruns',
    'remove_autorun',

    # Restrictions
    'RestrictionsManager',
    'get_restrictions',
    'remove_all_restrictions',

    # System
    'SystemCommands',
    'restart_pc',
    'enter_winre',
    'run_sfc',
    'disable_test_mode',

    # Recovery
    'WinREManager',
    'get_winre_status',
    'enable_winre',
    'disable_winre',
    'boot_to_winre',

    # Processes
    'ProcessManager',
    'get_processes',
    'terminate_process',
    'suspend_process',
    'resume_process',

    # Registry
    'RegistryEditor',
    'read_registry',
    'write_registry',
    'delete_registry',
    'open_regedit',
]

#!/usr/bin/env python3
"""
Startup configuration manager for Password Manager
"""
import os
import sys
import platform
import shutil

def get_startup_path():
    """Get the appropriate startup path for the current OS"""
    system = platform.system()
    if system == "Windows":
        return os.path.join(os.getenv('APPDATA'), 
                          'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
    elif system == "Linux":
        return os.path.expanduser('~/.config/autostart')
    else:
        return None

def create_startup_entry(enable=True):
    """Create or remove startup entry"""
    startup_path = get_startup_path()
    if not startup_path:
        return False

    system = platform.system()
    app_path = os.path.abspath(sys.argv[0])
    
    if system == "Windows":
        shortcut_path = os.path.join(startup_path, 'password_manager.bat')
        if enable:
            with open(shortcut_path, 'w') as f:
                f.write(f'@echo off\npythonw "{app_path}"')
        else:
            if os.path.exists(shortcut_path):
                os.remove(shortcut_path)
    
    elif system == "Linux":
        desktop_entry = os.path.join(startup_path, 'password_manager.desktop')
        if enable:
            os.makedirs(startup_path, exist_ok=True)
            with open(desktop_entry, 'w') as f:
                f.write(f"""[Desktop Entry]
Type=Application
Name=Password Manager
Exec=python3 {app_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
""")
            os.chmod(desktop_entry, 0o755)
        else:
            if os.path.exists(desktop_entry):
                os.remove(desktop_entry)
    
    return True

def is_startup_enabled():
    """Check if startup is enabled"""
    startup_path = get_startup_path()
    if not startup_path:
        return False
    
    system = platform.system()
    if system == "Windows":
        return os.path.exists(os.path.join(startup_path, 'password_manager.bat'))
    elif system == "Linux":
        return os.path.exists(os.path.join(startup_path, 'password_manager.desktop'))
    
    return False

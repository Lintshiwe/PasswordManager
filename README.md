\# Windows Password Manager

A secure password manager application for Windows with encryption and modern GUI.

## Features

- Secure encryption using Fernet (symmetric encryption)
- Master password protection
- SQLite database for password storage
- Modern and beautiful GUI with custom styling
- Password generator
- Auto-logout for security
- Copy passwords to clipboard
- View and edit password entries
- Password visibility toggle
- Notes support for each entry
- Automatic credential detection and saving from web browsers
- Smart update detection for existing credentials
- Startup integration for Windows and Linux
- Settings management with customizable options
- Modern Windows 10/11 interface
- Browser password import from:
  - Google Chrome
  - Mozilla Firefox
  - Microsoft Edge
- Real-time credential monitoring:
  - Automatically detects when you enter credentials in browsers
  - Smart duplicate detection
  - One-click saving of new passwords
  - Supports all major browsers

## Requirements

- Windows 10 or later
- Python 3.6+
- Required packages:
  - cryptography (for secure encryption)
  - tkinter (for the GUI interface)
  - pywin32 (for Windows integration)
  - pyperclip (clipboard management)
  - keyboard (input monitoring)
  - browser-cookie3 (browser integration)
  - pycryptodome (browser password decryption)

## Installation

1. Clone or download this repository
2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the application:

```bash
python password_manager.py
```

On first run, you'll be prompted to create a master password. This password will be used to encrypt and decrypt your stored passwords.

### Settings

Access settings through the main interface:

- Enable/disable startup with system
- Configure auto-logout timer
- Customize monitoring options

### Startup Integration

The password manager can be configured to start automatically with Windows:

- Creates a startup entry in the Windows Startup folder
- Can be enabled/disabled in Settings
- Starts minimized to system tray

## Security Features

- All passwords are encrypted using Fernet symmetric encryption
- Master password is hashed using PBKDF2 with SHA256
- Auto-logout after 10 minutes of inactivity
- Passwords are never stored in plain text

## Development

The application is built using:

- tkinter for the GUI
- cryptography for secure encryption
- sqlite3 for data storage
- threading for auto-logout functionality

## License

This project is licensed under the MIT License.

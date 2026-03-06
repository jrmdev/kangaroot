import sqlite3
import os
import re
import importlib
import importlib.util
import sys
import logging

from Crypto.Hash import MD4
from pathlib import Path
from typing import Dict, List, Optional, Set
from job_manager import JobManager
from credential_store import get_encryption

__prog__ = 'kangaroot'
logger = logging.getLogger(__name__)

class ModuleRegistry:
    """Manages module registration, loading, and global variables"""
    
    def __init__(self):
        # Prefer the new DB name, but transparently reuse the legacy one if present.
        self.db_path = f"{__prog__}.db"
        self.conn = sqlite3.connect(self.db_path)
        self._init_database()

        self.loaded_modules = {}  # Track loaded modules: {module_path: module_data}
        self.file_observer = None
        self.app_ref = None  # Reference to the main app
        self.encryption = get_encryption()  # Initialize encryption
        logger.info(f"ModuleRegistry initialized (encryption: {self.encryption.enabled})")

    def _init_database(self):
        """Initialize the database schema with indexes."""
        cursor = self.conn.cursor()

        # Create tables
        cursor.execute('''CREATE TABLE IF NOT EXISTS modules
                          (path TEXT PRIMARY KEY,
                           class_name TEXT,
                           file_path TEXT,
                           description TEXT)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS module_options
                          (module_path TEXT,
                           option_name TEXT,
                           default_value TEXT,
                           required BOOL,
                           description TEXT,
                           PRIMARY KEY (module_path, option_name))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS globals
                          (var_name TEXT PRIMARY KEY, value TEXT)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS module_vars
                          (module_path TEXT, var_name TEXT, value TEXT,
                           PRIMARY KEY (module_path, var_name))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS credentials
                          (id INTEGER, domain TEXT, username TEXT, password TEXT, nthash text,
                           PRIMARY KEY (domain, username))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS history
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cmdline TEXT)''')

        # Create indexes for performance
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_credentials_domain_username
                         ON credentials(domain, username)''')

        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_credentials_id
                         ON credentials(id)''')

        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_module_vars_path
                         ON module_vars(module_path)''')

        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_module_options_path
                         ON module_options(module_path)''')

        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_modules_path
                         ON modules(path)''')

        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_history_id
                         ON history(id DESC)''')

        self.conn.commit()
        logger.debug("Database schema initialized with indexes")
    
    def register_modules_from_disk(self):
        """Scan modules directory and register all modules"""
        modules_dir = "modules"
        if not os.path.exists(modules_dir):
            print(f"Modules directory '{modules_dir}' not found")
            return
        
        # Clear existing module data
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM modules")
        cursor.execute("DELETE FROM module_options")
        self.conn.commit()
        
        # Scan for module files
        for root, dirs, files in os.walk(modules_dir):
            for file in sorted(files):
                if file.endswith('.py') and not file.startswith('__'):
                    file_path = os.path.join(root, file)
                    self._register_module_file(file_path)
        
        print(f"Registered {len(self.get_all_modules())} modules")

    def add_to_history(self, command: str):
        """Add command to history database"""
        if not command.strip():
            return
        
        cursor = self.conn.cursor()
        
        # Insert the new command
        cursor.execute("INSERT INTO history (cmdline) VALUES (?)", (command,))
        
        # Keep only the latest 100 commands
        cursor.execute("DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT 100)")
        
        self.conn.commit()

    def load_history(self) -> List[str]:
        """Load command history from database"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT cmdline FROM history ORDER BY id")
        return [row[0] for row in cursor.fetchall()]

    async def load_module(self, module_path: str, job_manager: JobManager):
        """Load and instantiate a module"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT class_name, file_path FROM modules WHERE path = ?", (module_path,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        class_name, file_path = row
        file_path = str(Path(__file__).parent / file_path)
        
        try:
            # Load the module file
            spec = importlib.util.spec_from_file_location("temp_module", file_path)
            if spec is None or spec.loader is None:
                return None
                
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Get the module class and instantiate it
            module_class = getattr(module, class_name)
            return module_class(self, job_manager)
            
        except Exception as e:
            print(f"Error loading module {module_path}: {e}")
            return None

    def _to_bool_str(self, var: str):
        return "Yes" if var.lower() in ['true', '1', 'yes'] else "No"

    def _register_module_file(self, file_path: str):
        """Register a single module file"""
        try:
            # Load the module file
            spec = importlib.util.spec_from_file_location("temp_module", file_path)
            if spec is None or spec.loader is None:
                print("Failed to create spec")
                return
        
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find classes that are defined in this specific file (not imported)
            for attr_name in dir(module):
                if not attr_name.startswith('__'):
                    attr = getattr(module, attr_name)
                    
                    # Check if it's a class and has the required attributes
                    if (hasattr(attr, 'path') and hasattr(attr, 'description') and hasattr(attr, 'options')):
                        # Additional check: ensure this class is actually defined in this file
                        # by checking if the module where the class is defined matches our current module
                        if hasattr(attr, '__module__') and attr.__module__ == module.__name__:
                            path = getattr(attr, 'path', '')
                            description = getattr(attr, 'description', '')
                            options = getattr(attr, 'options', {})
                            
                            # Only register if it's not the base class and has actual values
                            if attr_name != 'BaseModule' and path and path != '':
                                cursor = self.conn.cursor()
                                cursor.execute("""INSERT OR REPLACE INTO modules
                                                (path, class_name, file_path, description)
                                                VALUES (?, ?, ?, ?)""",
                                            (path, attr_name, file_path, description))
                        
                                # Register module options
                                for opt_name, opt_info in options.items():
                                    cursor.execute("""INSERT OR REPLACE INTO module_options
                                                    (module_path, option_name, default_value, required, description)
                                                    VALUES (?, ?, ?, ?, ?)""",
                                                (path, opt_name, opt_info['default'], opt_info['required'], opt_info['description']))
                        
                                self.conn.commit()
                                print(f"Registered module: {path} (class: {attr_name})")
                                return
                    
        except Exception as e:
            print(f"Error registering module {file_path}: {e}")
    
    def get_all_modules(self) -> List[Dict]:
        """Get all registered modules"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT path, description FROM modules ORDER BY path")
        return [{'path': row[0], 'description': row[1]} for row in cursor.fetchall()]
    
    def get_module_suggestions(self, partial: str) -> List[str]:
        """Get module path suggestions for tab completion"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT path FROM modules WHERE path LIKE ? ORDER BY path", 
                      (f"{partial}%",))
        suggestions = [row[0] for row in cursor.fetchall()]
        return sorted(set(suggestions))
    
    def _get_module_name(self, module_path: str) -> str:
        """Generate consistent module name for sys.modules"""
        return f"dynamic_module_{module_path.replace('/', '_').replace('-', '_')}"
    
    def get_all_option_names(self) -> Set[str]:
        """Get all unique option names across all modules"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT option_name FROM module_options")
        return {row[0] for row in cursor.fetchall()}
    
    def set_global_var(self, var: str, val: str, is_bool: bool=False):
        """Set a global variable"""
        if is_bool:
            val = self._to_bool_str(val)
        cursor = self.conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO globals (var_name, value) VALUES (?, ?)", 
                      (var, val))
        self.conn.commit()

    def unset_global_var(self, var: str):
        """Unset a global variable"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM globals WHERE var_name=?", (var,))
        self.conn.commit()

    def get_global_var(self, var: str) -> Optional[str]:
        """Get a global variable value"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM globals WHERE var_name=?", (var,))
        row = cursor.fetchone()
        return row[0] if row else None
    
    def get_all_globals(self) -> Dict[str, str]:
        """Get all global variables"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT var_name, value FROM globals")
        return {row[0]: row[1] for row in cursor.fetchall()}

    def set_module_var(self, module_path: str, var: str, val: str, is_bool: bool=False):
        """Set a module-specific variable"""
        if is_bool:
            val = self._to_bool_str(val)
        cursor = self.conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO module_vars (module_path, var_name, value) VALUES (?, ?, ?)",
                      (module_path, var, val))
        self.conn.commit()

    def unset_module_var(self, module_path: str, var: str):
        """Unset a module-specific variable"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM module_vars WHERE module_path=? AND var_name=?", 
                      (module_path, var))
        self.conn.commit()

    def get_module_var(self, module_path: str, var: str) -> Optional[str]:
        """Get a module-specific variable"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM module_vars WHERE module_path=? AND var_name=?", 
                      (module_path, var))
        row = cursor.fetchone()
        return row[0] if row else None

    def get_option_default(self, module_path: str, option_name: str) -> Optional[str]:
        """Get the default value for a module option"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT default_value FROM module_options WHERE module_path=? AND option_name=?",
                      (module_path, option_name))
        row = cursor.fetchone()
        return row[0] if row else None

    def add_credential(self, domain: str, username: str, password_or_nthash: str) -> int:
        """
        Add a credential to the database with encryption.

        Args:
            domain: Domain name
            username: Username
            password_or_nthash: Password or NT hash

        Returns:
            Credential ID if added, 0 if already exists, -1 on error
        """
        try:
            cursor = self.conn.cursor()

            # Determine if it's a hash or password
            if re.match(r'^[a-fA-F0-9]{32}$', password_or_nthash):
                password = ""
                nthash = password_or_nthash.lower()
            else:
                password = password_or_nthash
                nthash = self._calculate_nthash(password)

            # Check if credential already exists
            cursor.execute(
                "SELECT id FROM credentials WHERE lower(domain)=? and lower(username)=? and (lower(password)=? or lower(nthash)=?)",
                (domain.lower(), username.lower(), password.lower(), nthash.lower())
            )
            res = cursor.fetchone()

            if res:
                logger.info(f"Credential already exists for {username}@{domain}")
                return 0

            # Encrypt sensitive data before storing
            encrypted_password = self.encryption.encrypt(password) if password else ""
            encrypted_nthash = self.encryption.encrypt(nthash)

            cursor.execute("SELECT MAX(id) FROM credentials")
            max_id = cursor.fetchone()[0]
            new_id = (max_id + 1) if max_id is not None else 1

            cursor.execute("""INSERT OR REPLACE INTO credentials
                            (id, domain, username, password, nthash)
                            VALUES (?, ?, ?, ?, ?)""",
                        (new_id, domain, username, encrypted_password, encrypted_nthash))
            self.conn.commit()

            logger.info(f"Added credential {new_id} for {username}@{domain}")
            return new_id

        except Exception as e:
            logger.error(f"Error adding credential: {e}", exc_info=True)
            return -1

    def delete_credential(self, cred_id: int) -> bool:
        """Delete a credential by ID"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id=?", (cred_id,))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        return deleted

    def list_credentials(self, cred_id: Optional[int] = None) -> List[Dict]:
        """
        List credentials, optionally filtered by ID (with decryption).

        Args:
            cred_id: Optional credential ID to filter

        Returns:
            List of credential dictionaries
        """
        try:
            cursor = self.conn.cursor()

            if cred_id is not None:
                cursor.execute("""SELECT id, domain, username, password, nthash FROM credentials WHERE id=? ORDER BY id ASC""", (cred_id,))
            else:
                cursor.execute("""SELECT id, domain, username, password, nthash FROM credentials ORDER BY id ASC""")

            credentials = []
            for row in cursor.fetchall():
                # Decrypt sensitive data
                password = self.encryption.decrypt(row[3]) if row[3] else ""
                nthash = self.encryption.decrypt(row[4]) if row[4] else ""

                credentials.append({
                    'id': row[0],
                    'domain': row[1],
                    'username': row[2],
                    'password': password,
                    'nthash': nthash
                })

            return credentials

        except Exception as e:
            logger.error(f"Error listing credentials: {e}", exc_info=True)
            return []

    def find_credentials(self, term: str) -> List[Dict]:
        """
        Find credentials by search term (with decryption).

        Args:
            term: Search term to match against username

        Returns:
            List of matching credential dictionaries
        """
        try:
            cursor = self.conn.cursor()

            if not term:
                return []

            term = f"%{term}%"
            cursor.execute("""SELECT id, domain, username, password, nthash FROM credentials WHERE username LIKE ? ORDER BY id ASC""", (term,))

            credentials = []
            for row in cursor.fetchall():
                # Decrypt sensitive data
                password = self.encryption.decrypt(row[3]) if row[3] else ""
                nthash = self.encryption.decrypt(row[4]) if row[4] else ""

                credentials.append({
                    'id': row[0],
                    'domain': row[1],
                    'username': row[2],
                    'password': password,
                    'nthash': nthash
                })

            return credentials

        except Exception as e:
            logger.error(f"Error finding credentials: {e}", exc_info=True)
            return []

    def get_credentials(self, cred_id: int):
        """
        Get specific credential by ID (with decryption).

        Args:
            cred_id: Credential ID

        Returns:
            Tuple of (domain, username, password/hash) or None if not found
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""SELECT id, domain, username, password, nthash FROM credentials WHERE id=?""", (cred_id,))

            for row in cursor.fetchall():
                domain = row[1]
                username = row[2]
                # Decrypt sensitive data
                password = self.encryption.decrypt(row[3]) if row[3] else ""
                nthash = self.encryption.decrypt(row[4]) if row[4] else ""

                # Use hash if password is empty
                if password == "":
                    password = nthash

                logger.debug(f"Retrieved credential {cred_id} for {username}@{domain}")
                return domain, username, password

            return None

        except Exception as e:
            logger.error(f"Error getting credentials: {e}", exc_info=True)
            return None

    def _calculate_nthash(self, password: str) -> str:
        """Calculate NT hash from password"""
        password_utf16le = password.encode('utf-16le')
        md4_hash = MD4.new(password_utf16le)
        return md4_hash.hexdigest().lower()

    def close(self):
        """Close the database connection"""
        if self.file_observer:
            stop = getattr(self, "stop_hot_reload", None)
            if callable(stop):
                stop()
        self.conn.close()

    def stop_hot_reload(self) -> None:
        """Stop filesystem observer if hot reload is enabled."""
        observer = self.file_observer
        if not observer:
            return

        try:
            stop = getattr(observer, "stop", None)
            join = getattr(observer, "join", None)
            if callable(stop):
                stop()
            if callable(join):
                join(timeout=1)
        except Exception as e:
            logger.debug(f"Failed stopping hot reload observer: {e}")
        finally:
            self.file_observer = None

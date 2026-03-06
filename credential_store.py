"""
Secure credential storage with encryption.

This module provides encrypted storage for credentials, replacing
the plaintext storage in the database.
"""

import os
import stat
import logging
from pathlib import Path
from typing import Optional
from typing import Any

logger = logging.getLogger(__name__)


class CredentialEncryption:
    """
    Handles encryption and decryption of credentials.

    Uses Fernet symmetric encryption with a key stored in user's home directory.
    Falls back to no encryption if cryptography library is not available.
    """

    def __init__(self, key_file: Optional[str] = None):
        """
        Initialize credential encryption.

        Args:
            key_file: Path to encryption key file (defaults to ~/.kangaroot/encryption.key)
        """
        self.enabled = False
        self.cipher: Optional[Any] = None
        self._Fernet: Optional[Any] = None

        try:
            from cryptography.fernet import Fernet
            self._Fernet = Fernet
            self.enabled = True
        except ImportError:
            logger.warning("cryptography library not available - credentials will not be encrypted")
            logger.warning("Install with: pip install cryptography")
            return

        # Determine key file path
        if key_file is None:
            key_dir = Path.home() / '.kangaroot'

            key_dir.mkdir(parents=True, exist_ok=True)
            key_file = str(key_dir / 'encryption.key')

        self.key_file = key_file
        self._load_or_create_key()

    def _load_or_create_key(self) -> None:
        """Load existing encryption key or create a new one."""
        fernet_cls = self._Fernet
        if not self.enabled or fernet_cls is None:
            self.enabled = False
            self.cipher = None
            return

        assert fernet_cls is not None

        if os.path.exists(self.key_file):
            # Load existing key
            try:
                with open(self.key_file, 'rb') as f:
                    key = f.read()
                self.cipher = fernet_cls(key)
                logger.info(f"Loaded encryption key from {self.key_file}")
            except Exception as e:
                logger.error(f"Failed to load encryption key: {e}")
                self.enabled = False
                self.cipher = None
                return
        else:
            # Create new key
            try:
                key = fernet_cls.generate_key()

                # Write key with secure permissions
                os.makedirs(os.path.dirname(self.key_file), exist_ok=True)

                # Create file with owner-only permissions
                fd = os.open(self.key_file, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as f:
                    f.write(key)

                self.cipher = fernet_cls(key)
                logger.info(f"Created new encryption key at {self.key_file}")

                # Double-check permissions (for Windows compatibility)
                try:
                    os.chmod(self.key_file, stat.S_IRUSR | stat.S_IWUSR)
                except Exception as e:
                    logger.warning(f"Could not set file permissions: {e}")

            except Exception as e:
                logger.error(f"Failed to create encryption key: {e}")
                self.enabled = False
                self.cipher = None
                return

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string.

        Args:
            plaintext: String to encrypt

        Returns:
            Encrypted string (base64 encoded), or plaintext if encryption disabled
        """
        cipher = self.cipher
        if not self.enabled or cipher is None or not plaintext:
            return plaintext

        try:
            encrypted = cipher.encrypt(plaintext.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return plaintext

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt a string.

        Args:
            ciphertext: Encrypted string (base64 encoded)

        Returns:
            Decrypted string, or ciphertext if decryption fails
        """
        cipher = self.cipher
        if not self.enabled or cipher is None or not ciphertext:
            return ciphertext

        try:
            decrypted = cipher.decrypt(ciphertext.encode())
            return decrypted.decode()
        except Exception as e:
            # Might be plaintext from old database
            logger.debug(f"Decryption failed (might be plaintext): {e}")
            return ciphertext

    def is_encrypted(self, text: str) -> bool:
        """
        Check if a string appears to be encrypted.

        Args:
            text: String to check

        Returns:
            True if string appears to be encrypted (base64 Fernet format)
        """
        if not self.enabled or not text:
            return False

        # Fernet tokens start with 'gAAAAA' after base64 encoding
        return text.startswith('gAAAAA')


# Global instance
_encryption_instance: Optional[CredentialEncryption] = None


def get_encryption() -> CredentialEncryption:
    """
    Get the global encryption instance (singleton pattern).

    Returns:
        CredentialEncryption instance
    """
    global _encryption_instance
    if _encryption_instance is None:
        _encryption_instance = CredentialEncryption()
    return _encryption_instance


def encrypt_password(password: str) -> str:
    """
    Convenience function to encrypt a password.

    Args:
        password: Password to encrypt

    Returns:
        Encrypted password
    """
    return get_encryption().encrypt(password)


def decrypt_password(encrypted: str) -> str:
    """
    Convenience function to decrypt a password.

    Args:
        encrypted: Encrypted password

    Returns:
        Decrypted password
    """
    return get_encryption().decrypt(encrypted)

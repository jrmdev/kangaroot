"""Centralized authentication management for Kangaroot.

This module provides a unified interface for building authentication parameters
for various tools (Impacket, Certipy, BloodyAD, etc.) with support for both
NTLM and Kerberos authentication.
"""

import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List
from validators import ValidationError, validate_auth_type, is_nt_hash

EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


class AuthType(Enum):
    """Authentication types supported."""

    NTLM = "ntlm"
    KERBEROS = "krb"


@dataclass
class Credentials:
    """
    Credential container with validation.

    Attributes:
        auth_type: Type of authentication (NTLM or Kerberos)
        domain: Domain name
        username: Username (without domain suffix)
        password: Password or NT hash (for NTLM)
        ticket_path: Path to Kerberos ticket file (for Kerberos)
    """

    auth_type: AuthType
    domain: str
    username: str
    password: Optional[str] = None
    ticket_path: Optional[str] = None

    def __post_init__(self):
        """Validate credentials after initialization."""
        # Clean username (remove domain suffix if present)
        if "@" in self.username:
            self.username = self.username.split("@")[0]
        if "\\" in self.username:
            self.username = self.username.split("\\")[1]

    def validate(self) -> None:
        """
        Validate credential completeness based on auth type.

        Raises:
            ValidationError: If credentials are incomplete or invalid
        """
        if not self.domain:
            raise ValidationError("Domain is required")

        if not self.username:
            raise ValidationError("Username is required")

        if self.auth_type == AuthType.NTLM:
            if not self.password:
                raise ValidationError(
                    "Password or NT hash required for NTLM authentication"
                )

        elif self.auth_type == AuthType.KERBEROS:
            if not self.ticket_path:
                raise ValidationError(
                    "Ticket path required for Kerberos authentication"
                )
            if not os.path.exists(self.ticket_path):
                raise ValidationError(f"Kerberos ticket not found: {self.ticket_path}")

    def is_hash_auth(self) -> bool:
        """Check if using hash-based authentication."""
        return bool(self.password) and is_nt_hash(self.password)


class AuthManager:
    """
    Centralized authentication parameter builder for various tools.

    This class consolidates authentication logic that was previously duplicated
    across multiple methods in BaseModule and Tool classes.
    """

    def __init__(self, credentials: Credentials, env: dict, logs_dir: str):
        """
        Initialize AuthManager.

        Args:
            credentials: Authentication credentials
            env: Environment variables dictionary
            logs_dir: Directory for logs and tickets
        """
        self.credentials = credentials
        self.env = env
        self.logs_dir = logs_dir
        self._setup_environment()

    def _setup_environment(self) -> None:
        """Configure environment variables based on auth type."""
        if self.credentials.auth_type == AuthType.KERBEROS:
            if self.credentials.ticket_path:
                self.env["KRB5CCNAME"] = self.credentials.ticket_path
        elif self.credentials.auth_type == AuthType.NTLM:
            # Remove Kerberos ticket from environment for NTLM
            if "KRB5CCNAME" in self.env:
                del self.env["KRB5CCNAME"]

    def _format_lm_nt_hash(self, nt_hash: str) -> str:
        """Return hash string in LM:NT format using the empty LM hash."""
        return f"{EMPTY_LM_HASH}:{nt_hash}"

    def get_impacket_params(self, target: Optional[str] = None) -> List[str]:
        """
        Build authentication parameters for Impacket tools.

        Args:
            target: Optional target hostname/IP

        Returns:
            List of command-line parameters

        Example:
            For NTLM: ['DOMAIN/user:password@target']
            For NTLM hash: ['-hashes', 'aad3...:hash', 'DOMAIN/user@target']
            For Kerberos: ['-k', '-no-pass', '@target']
        """
        if self.credentials.auth_type == AuthType.KERBEROS:
            params = ["-k", "-no-pass"]
            if target:
                # Impacket expects target in specific format for Kerberos
                if "/" not in target and "@" not in target:
                    params.append("@" + target)
                else:
                    params.append(target)
            return params

        # NTLM authentication
        target_str = "@" + target if target else ""
        user_spec = f"{self.credentials.domain}/{self.credentials.username}"

        if self.credentials.is_hash_auth():
            # Hash authentication
            assert self.credentials.password is not None
            return [
                "-hashes",
                self._format_lm_nt_hash(self.credentials.password),
                f"{user_spec}{target_str}",
            ]
        else:
            # Password authentication
            assert self.credentials.password is not None
            return [f"{user_spec}:{self.credentials.password}{target_str}"]

    def get_certipy_params(self) -> List[str]:
        """
        Build authentication parameters for Certipy.

        Returns:
            List of command-line parameters

        Example:
            For NTLM: ['-u', 'user@DOMAIN', '-p', 'password']
            For NTLM hash: ['-hashes', 'aad3...:hash', '-u', 'user@DOMAIN']
            For Kerberos: ['-k', '-no-pass']
        """
        if self.credentials.auth_type == AuthType.KERBEROS:
            return ["-k", "-no-pass"]

        # NTLM authentication
        user_spec = f"{self.credentials.username}@{self.credentials.domain}"

        if self.credentials.is_hash_auth():
            assert self.credentials.password is not None
            return [
                "-hashes",
                self._format_lm_nt_hash(self.credentials.password),
                "-u",
                user_spec,
            ]
        else:
            assert self.credentials.password is not None
            return ["-u", user_spec, "-p", self.credentials.password]

    def get_bloodyad_params(self) -> List[str]:
        """
        Build authentication parameters for BloodyAD.

        Returns:
            List of command-line parameters

        Example:
            For NTLM: ['-u', 'user', '-d', 'DOMAIN', '-p', 'password']
            For NTLM hash: ['-u', 'user', '-d', 'DOMAIN', '-p', 'aad3...:hash']
            For Kerberos: ['-k', '-d', 'DOMAIN']
        """
        if self.credentials.auth_type == AuthType.KERBEROS:
            return ["-k", "-d", self.credentials.domain]

        # NTLM authentication
        if self.credentials.is_hash_auth():
            assert self.credentials.password is not None
            pass_val = self._format_lm_nt_hash(self.credentials.password)
        else:
            assert self.credentials.password is not None
            pass_val = self.credentials.password

        return [
            "-u",
            self.credentials.username,
            "-d",
            self.credentials.domain,
            "-p",
            pass_val,
        ]

    def get_petitpotam_params(self) -> List[str]:
        """
        Build authentication parameters for PetitPotam.

        Returns:
            List of command-line parameters

        Example:
            For NTLM: ['-u', 'user', '-d', 'DOMAIN', '-p', 'password']
            For NTLM hash: ['-hashes', 'aad3...:hash', '-u', 'user', '-d', 'DOMAIN']
            For Kerberos: ['-k', '-no-pass']
        """
        if self.credentials.auth_type == AuthType.KERBEROS:
            return ["-k", "-no-pass"]

        # NTLM authentication
        if self.credentials.is_hash_auth():
            assert self.credentials.password is not None
            return [
                "-hashes",
                self._format_lm_nt_hash(self.credentials.password),
                "-u",
                self.credentials.username,
                "-d",
                self.credentials.domain,
            ]
        else:
            assert self.credentials.password is not None
            return [
                "-u",
                self.credentials.username,
                "-d",
                self.credentials.domain,
                "-p",
                self.credentials.password,
            ]

    def get_krbrelayx_params(self) -> List[str]:
        """
        Build authentication parameters for krbrelayx tools.

        Returns:
            List of command-line parameters

        Example:
            For NTLM: ['-u', 'DOMAIN\\user', '-p', 'password']
            For NTLM hash: ['-u', 'DOMAIN\\user', '-p', 'LM:NTLM']
            For Kerberos: ['-k']
        """
        if self.credentials.auth_type == AuthType.KERBEROS:
            return ["-k"]

        # NTLM authentication
        user_spec = f"{self.credentials.domain}\\{self.credentials.username}"

        if self.credentials.is_hash_auth():
            # krbrelayx expects LM:NTLM format.
            assert self.credentials.password is not None
            pass_val = self._format_lm_nt_hash(self.credentials.password)
        else:
            assert self.credentials.password is not None
            pass_val = self.credentials.password

        return ["-u", user_spec, "-p", pass_val]

    def get_default_ticket_path(self) -> str:
        """
        Get default ticket path for current user.

        Returns:
            Path to ticket file
        """
        ticket_name = f"{self.credentials.username.lower()}.ccache"
        return os.path.join(self.logs_dir, ticket_name)

    @classmethod
    def from_module_options(cls, module, skip_validation: bool = False):
        """
        Create AuthManager from module options.

        Args:
            module: BaseModule instance with opts attribute
            skip_validation: Skip credential validation if True

        Returns:
            AuthManager instance

        Raises:
            ValidationError: If credentials are invalid
        """
        # Get values from module options
        auth_str = str(getattr(module.opts, "auth", "ntlm"))
        domain = getattr(module.opts, "domain", "")
        username = getattr(module.opts, "username", "")
        password = getattr(module.opts, "password", "")

        # Normalize auth type
        try:
            auth_str = validate_auth_type(auth_str)
        except ValidationError:
            auth_str = "ntlm"

        auth_type = AuthType.KERBEROS if auth_str == "krb" else AuthType.NTLM

        # Determine ticket path for Kerberos
        ticket_path = None
        if auth_type == AuthType.KERBEROS:
            ticket_name = f"{username.lower()}.ccache"
            ticket_path = os.path.join(module.logs_dir, ticket_name)

        # Create credentials
        credentials = Credentials(
            auth_type=auth_type,
            domain=domain,
            username=username,
            password=password if password else None,
            ticket_path=ticket_path,
        )

        # Validate if requested
        if not skip_validation:
            credentials.validate()

        return cls(credentials, module.env, module.logs_dir)

    @classmethod
    def create(
        cls,
        auth_type: str,
        domain: str,
        username: str,
        password: Optional[str] = None,
        ticket_path: Optional[str] = None,
        env: Optional[dict] = None,
        logs_dir: Optional[str] = None,
    ):
        """
        Create AuthManager with explicit parameters.

        Args:
            auth_type: 'ntlm' or 'krb'
            domain: Domain name
            username: Username
            password: Password or NT hash (for NTLM)
            ticket_path: Path to ticket file (for Kerberos)
            env: Environment variables (uses os.environ if not provided)
            logs_dir: Logs directory (uses current dir if not provided)

        Returns:
            AuthManager instance
        """
        if env is None:
            env = os.environ.copy()

        if logs_dir is None:
            logs_dir = os.getcwd()

        normalized_auth = "ntlm"
        try:
            normalized_auth = validate_auth_type(auth_type)
        except ValidationError:
            pass

        auth_type_enum = AuthType.KERBEROS if normalized_auth == "krb" else AuthType.NTLM

        credentials = Credentials(
            auth_type=auth_type_enum,
            domain=domain,
            username=username,
            password=password,
            ticket_path=ticket_path,
        )

        return cls(credentials, env, logs_dir)

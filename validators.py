"""Input validation utilities for Kangaroot.

This module provides validation functions for common input types used throughout
the application, ensuring data integrity and security.
"""

import re
import ipaddress
from typing import Optional


class ValidationError(Exception):
    """Raised when validation fails."""
    pass


def validate_domain(domain: str) -> str:
    """
    Validate and normalize domain name.

    Args:
        domain: Domain name to validate (e.g., 'example.com', 'corp.example.com')

    Returns:
        Normalized (lowercase) domain name

    Raises:
        ValidationError: If domain format is invalid
    """
    if not domain:
        raise ValidationError("Domain cannot be empty")

    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
        raise ValidationError(f"Invalid domain format: {domain}")

    if len(domain) > 253:
        raise ValidationError(f"Domain name too long: {domain}")

    return domain.lower()


def validate_username(username: str) -> str:
    """
    Validate username format.

    Args:
        username: Username to validate

    Returns:
        Validated username

    Raises:
        ValidationError: If username format is invalid
    """
    if not username:
        raise ValidationError("Username cannot be empty")

    # Remove domain suffix if present (user@domain.com -> user)
    if '@' in username:
        username = username.split('@')[0]

    # Remove domain prefix if present (DOMAIN\user -> user)
    if '\\' in username:
        username = username.split('\\')[1]

    # Check length (SAM account name limit is 20, but userPrincipalName can be longer)
    if len(username) > 104:
        raise ValidationError(f"Username too long (max 104 characters): {username}")

    # Check for invalid characters (basic validation)
    if re.search(r'["/\[\]:;|=,+*?<>]', username):
        raise ValidationError(f"Username contains invalid characters: {username}")

    return username


def validate_password(password: str) -> str:
    """
    Validate password (minimal validation for now).

    Args:
        password: Password or hash to validate

    Returns:
        Validated password

    Raises:
        ValidationError: If password is invalid
    """
    if not password:
        raise ValidationError("Password cannot be empty")

    # For now, just check it's not empty. Could add complexity requirements later
    return password


def validate_ip_address(ip: str) -> str:
    """
    Validate IP address format.

    Args:
        ip: IP address to validate

    Returns:
        Validated IP address

    Raises:
        ValidationError: If IP address format is invalid
    """
    if not ip:
        raise ValidationError("IP address cannot be empty")

    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise ValidationError(f"Invalid IP address: {ip}")


def validate_hostname(hostname: str) -> str:
    """
    Validate hostname format.

    Args:
        hostname: Hostname to validate

    Returns:
        Validated hostname

    Raises:
        ValidationError: If hostname format is invalid
    """
    if not hostname:
        raise ValidationError("Hostname cannot be empty")

    # Check if it's an IP address (also valid)
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    # Validate as hostname
    if len(hostname) > 253:
        raise ValidationError(f"Hostname too long: {hostname}")

    # Basic hostname validation
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', hostname):
        raise ValidationError(f"Invalid hostname format: {hostname}")

    return hostname


def validate_nt_hash(hash_string: str) -> str:
    """
    Validate NT hash format.

    Args:
        hash_string: Hash string to validate

    Returns:
        Validated (uppercase) hash

    Raises:
        ValidationError: If hash format is invalid
    """
    if not hash_string:
        raise ValidationError("Hash cannot be empty")

    # Remove leading/trailing colons
    hash_string = hash_string.strip(':')

    # Check format (32 hexadecimal characters)
    if not re.fullmatch(r'[0-9a-fA-F]{32}', hash_string):
        raise ValidationError(f"Invalid NT hash format (expected 32 hex characters): {hash_string}")

    return hash_string.upper()


def validate_auth_type(auth_type: str) -> str:
    """
    Validate authentication type.

    Args:
        auth_type: Authentication type ('ntlm', 'krb', 'kerberos')

    Returns:
        Normalized auth type ('ntlm' or 'krb')

    Raises:
        ValidationError: If auth type is invalid
    """
    if not auth_type:
        raise ValidationError("Auth type cannot be empty")

    auth_type = auth_type.lower()

    # Normalize kerberos to krb
    if auth_type == 'kerberos':
        auth_type = 'krb'

    if auth_type not in ['ntlm', 'krb']:
        raise ValidationError(f"Invalid auth type (must be 'ntlm' or 'krb'): {auth_type}")

    return auth_type


def is_nt_hash(s: str) -> bool:
    """
    Check if a string is a valid NT hash without raising exceptions.

    Args:
        s: String to check

    Returns:
        True if string is a valid NT hash format, False otherwise
    """
    if not isinstance(s, str):
        return False

    s = s.strip(':')
    return bool(re.fullmatch(r'[0-9a-fA-F]{32}', s))


def validate_module_path(path: str) -> str:
    """
    Validate module path format.

    Args:
        path: Module path (e.g., 'acl/setpasswd')

    Returns:
        Validated module path

    Raises:
        ValidationError: If path format is invalid
    """
    if not path:
        raise ValidationError("Module path cannot be empty")

    # Check for invalid characters
    if not re.match(r'^[a-z0-9_/]+$', path):
        raise ValidationError(f"Invalid module path format: {path}")

    # Check for consecutive slashes
    if '//' in path:
        raise ValidationError(f"Module path contains consecutive slashes: {path}")

    # Check for leading/trailing slashes
    if path.startswith('/') or path.endswith('/'):
        raise ValidationError(f"Module path cannot start or end with slash: {path}")

    return path

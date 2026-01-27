"""Credential storage using system keyring with encrypted file fallback."""

import base64
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SERVICE_NAME = "graboid"


@dataclass
class Credential:
    """Stored credential."""

    name: str
    username: str
    password: str
    metadata: dict[str, Any] | None = None


class CredentialStore:
    """Manages credentials using system keyring or encrypted file fallback.

    Attempts to use the system keyring (via keyring library) for secure storage.
    Falls back to an encrypted JSON file when keyring is unavailable (e.g., headless servers).
    """

    def __init__(self, config_dir: Path | None = None):
        """Initialize credential store.

        Args:
            config_dir: Directory for fallback encrypted storage.
                       Defaults to ~/.config/graboid/
        """
        self._config_dir = config_dir or Path.home() / ".config" / "graboid"
        self._keyring_available: bool | None = None
        self._fallback_key: bytes | None = None

    @property
    def keyring_available(self) -> bool:
        """Check if system keyring is available.

        Note: Disabled by default to avoid GUI password prompts.
        Uses encrypted file fallback instead which doesn't require user interaction.
        Set GRABOID_USE_KEYRING=1 to enable system keyring.
        """
        if self._keyring_available is None:
            # Disabled by default to avoid GUI prompts for keyring unlock
            if not os.environ.get("GRABOID_USE_KEYRING"):
                self._keyring_available = False
                return self._keyring_available

            try:
                import keyring
                from keyring.backends.fail import Keyring as FailKeyring

                # Check if we have a working backend
                backend = keyring.get_keyring()
                self._keyring_available = not isinstance(backend, FailKeyring)

            except ImportError:
                self._keyring_available = False
            except Exception as e:
                logger.debug(f"Keyring check failed: {e}")
                self._keyring_available = False

        return self._keyring_available

    @property
    def _fallback_file(self) -> Path:
        """Path to encrypted fallback credentials file."""
        return self._config_dir / "credentials.enc"

    @property
    def _index_file(self) -> Path:
        """Path to credential names index (for keyring mode)."""
        return self._config_dir / "credential_names.json"

    def _get_fallback_key(self, master_password: str | None = None) -> bytes:
        """Get or derive the encryption key for fallback storage."""
        if self._fallback_key:
            return self._fallback_key

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        # Use master password or derive from machine-specific data
        if master_password:
            password = master_password.encode()
        else:
            # Use combination of machine ID and username as fallback key material
            machine_id = self._get_machine_id()
            password = f"{machine_id}:{os.getlogin()}".encode()

        # Use static salt (stored with credentials) or generate
        salt_file = self._config_dir / ".salt"
        if salt_file.exists():
            salt = salt_file.read_bytes()
        else:
            salt = os.urandom(16)
            self._config_dir.mkdir(parents=True, exist_ok=True)
            salt_file.write_bytes(salt)
            salt_file.chmod(0o600)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )

        self._fallback_key = base64.urlsafe_b64encode(kdf.derive(password))
        return self._fallback_key

    def _get_machine_id(self) -> str:
        """Get a machine-specific identifier."""
        # Try various sources
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
            try:
                return Path(path).read_text().strip()
            except Exception:
                pass

        # Fallback to hostname
        import socket

        return socket.gethostname()

    def _encrypt_data(self, data: dict[str, Any], master_password: str | None = None) -> bytes:
        """Encrypt data using Fernet."""
        from cryptography.fernet import Fernet

        key = self._get_fallback_key(master_password)
        f = Fernet(key)
        return f.encrypt(json.dumps(data).encode())

    def _decrypt_data(self, encrypted: bytes, master_password: str | None = None) -> dict[str, Any]:
        """Decrypt data using Fernet."""
        from cryptography.fernet import Fernet

        key = self._get_fallback_key(master_password)
        f = Fernet(key)
        return json.loads(f.decrypt(encrypted).decode())

    def _load_fallback_credentials(self, master_password: str | None = None) -> dict[str, dict[str, Any]]:
        """Load credentials from encrypted fallback file."""
        if not self._fallback_file.exists():
            return {}

        try:
            encrypted = self._fallback_file.read_bytes()
            return self._decrypt_data(encrypted, master_password)
        except Exception as e:
            logger.error(f"Failed to decrypt credentials: {e}")
            return {}

    def _save_fallback_credentials(
        self, credentials: dict[str, dict[str, Any]], master_password: str | None = None
    ) -> None:
        """Save credentials to encrypted fallback file."""
        self._config_dir.mkdir(parents=True, exist_ok=True)
        encrypted = self._encrypt_data(credentials, master_password)
        self._fallback_file.write_bytes(encrypted)
        self._fallback_file.chmod(0o600)

    def _load_credential_names(self) -> list[str]:
        """Load list of credential names (for keyring mode)."""
        if not self._index_file.exists():
            return []
        try:
            return json.loads(self._index_file.read_text())
        except Exception:
            return []

    def _save_credential_names(self, names: list[str]) -> None:
        """Save list of credential names."""
        self._config_dir.mkdir(parents=True, exist_ok=True)
        self._index_file.write_text(json.dumps(sorted(set(names))))

    def add(
        self,
        name: str,
        username: str,
        password: str,
        metadata: dict[str, Any] | None = None,
        master_password: str | None = None,
    ) -> None:
        """Add or update a credential.

        Args:
            name: Unique name for this credential
            username: Username/login
            password: Password/secret
            metadata: Optional metadata (e.g., server, port)
            master_password: Master password for fallback encryption
        """
        if self.keyring_available:
            import keyring

            # Store as JSON in keyring
            data = {"username": username, "password": password, "metadata": metadata or {}}
            keyring.set_password(SERVICE_NAME, name, json.dumps(data))

            # Update index
            names = self._load_credential_names()
            if name not in names:
                names.append(name)
                self._save_credential_names(names)
        else:
            # Use encrypted file fallback
            credentials = self._load_fallback_credentials(master_password)
            credentials[name] = {
                "username": username,
                "password": password,
                "metadata": metadata or {},
            }
            self._save_fallback_credentials(credentials, master_password)

        logger.info(f"Credential '{name}' saved")

    def get(self, name: str, master_password: str | None = None) -> Credential | None:
        """Get a credential by name.

        Args:
            name: Credential name
            master_password: Master password for fallback decryption

        Returns:
            Credential if found, None otherwise
        """
        if self.keyring_available:
            import keyring

            data_str = keyring.get_password(SERVICE_NAME, name)
            if not data_str:
                return None

            try:
                data = json.loads(data_str)
                return Credential(
                    name=name,
                    username=data["username"],
                    password=data["password"],
                    metadata=data.get("metadata"),
                )
            except Exception as e:
                logger.error(f"Failed to parse credential '{name}': {e}")
                return None
        else:
            credentials = self._load_fallback_credentials(master_password)
            if name not in credentials:
                return None

            data = credentials[name]
            return Credential(
                name=name,
                username=data["username"],
                password=data["password"],
                metadata=data.get("metadata"),
            )

    def delete(self, name: str, master_password: str | None = None) -> bool:
        """Delete a credential.

        Args:
            name: Credential name
            master_password: Master password for fallback storage

        Returns:
            True if deleted, False if not found
        """
        if self.keyring_available:
            import keyring

            try:
                keyring.delete_password(SERVICE_NAME, name)
                names = self._load_credential_names()
                if name in names:
                    names.remove(name)
                    self._save_credential_names(names)
                logger.info(f"Credential '{name}' deleted")
                return True
            except keyring.errors.PasswordDeleteError:
                return False
        else:
            credentials = self._load_fallback_credentials(master_password)
            if name not in credentials:
                return False

            del credentials[name]
            self._save_fallback_credentials(credentials, master_password)
            logger.info(f"Credential '{name}' deleted")
            return True

    def list(self, master_password: str | None = None) -> list[str]:
        """List all credential names.

        Args:
            master_password: Master password for fallback decryption

        Returns:
            List of credential names
        """
        if self.keyring_available:
            return self._load_credential_names()
        else:
            credentials = self._load_fallback_credentials(master_password)
            return sorted(credentials.keys())

    def exists(self, name: str, master_password: str | None = None) -> bool:
        """Check if a credential exists.

        Args:
            name: Credential name
            master_password: Master password for fallback

        Returns:
            True if credential exists
        """
        return self.get(name, master_password) is not None

    def get_auth(self, name: str, master_password: str | None = None) -> tuple[str, str] | None:
        """Get username and password as a tuple (convenience method).

        Args:
            name: Credential name
            master_password: Master password for fallback

        Returns:
            (username, password) tuple if found, None otherwise
        """
        cred = self.get(name, master_password)
        if cred:
            return (cred.username, cred.password)
        return None

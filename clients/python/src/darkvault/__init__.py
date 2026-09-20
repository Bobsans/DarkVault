"""DarkVault's synchronous Python client."""

from .client import DarkVaultClient, DarkVaultError
from .configuration import SecretScalar, build_configuration

__all__ = ["DarkVaultClient", "DarkVaultError", "SecretScalar", "build_configuration"]

"""Python client for Dr.COM/ePortal campus network authentication."""

from .client import AuthenticationError, ClientInfo, LoginOptions, NetworkAuthenticator, PortalConfig

__all__ = ["AuthenticationError", "ClientInfo", "LoginOptions", "NetworkAuthenticator", "PortalConfig"]

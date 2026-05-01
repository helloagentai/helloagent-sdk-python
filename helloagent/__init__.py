from .client import (
    Agent,
    UserClient,
    IncomingMessage,
    AuthFailedError,
    register_user,
    login_user,
    claim_handle,
)
from .crypto import KeyPair, Session, load_public
from . import tokens, keystore, channels, discovery
from .tools import Tool, ToolRegistry

# register_user / login_user are kept exported but raise NotImplementedError —
# the relay no longer hosts /v1/auth/register or /v1/auth/login. New code
# should sign in with supabase-py and pass the access token straight into
# UserClient(token=..., handle=...). claim_handle wraps POST /v1/profile.
__all__ = [
    "Agent", "UserClient", "IncomingMessage", "AuthFailedError",
    "register_user", "login_user", "claim_handle",
    "KeyPair", "Session", "load_public",
    "Tool", "ToolRegistry",
    "tokens", "keystore", "channels", "discovery",
]

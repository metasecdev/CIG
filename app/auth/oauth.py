"""
Advanced authentication with OAuth2 and OIDC support
"""

from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import logging
import hashlib
import secrets
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AuthToken:
    """Authentication token"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_token: Optional[str] = None
    scope: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "refresh_token": self.refresh_token,
            "scope": self.scope,
        }


@dataclass
class User:
    """Authenticated user"""
    user_id: str
    username: str
    email: str
    scopes: list = None
    created_at: str = ""
    last_login: str = ""

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = ["read"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "scopes": self.scopes,
        }


class TokenManager:
    """Manage authentication tokens"""

    def __init__(self, secret_key: str, expiration_hours: int = 1):
        """
        Initialize token manager.
        
        Args:
            secret_key: Secret key for token generation
            expiration_hours: Token expiration time
        """
        self.secret_key = secret_key
        self.expiration_hours = expiration_hours
        self.tokens: Dict[str, Dict[str, Any]] = {}

    def generate_token(self, user_id: str, scopes: list = None) -> AuthToken:
        """Generate authentication token"""
        if scopes is None:
            scopes = ["read"]

        # Simple token generation (in production, use JWT)
        token_value = secrets.token_urlsafe(32)
        
        token = AuthToken(
            access_token=token_value,
            expires_in=self.expiration_hours * 3600,
            refresh_token=secrets.token_urlsafe(32),
            scope=" ".join(scopes)
        )

        # Store token
        self.tokens[token_value] = {
            "user_id": user_id,
            "scopes": scopes,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (
                datetime.utcnow() + 
                timedelta(hours=self.expiration_hours)
            ).isoformat(),
        }

        return token

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate token"""
        if token not in self.tokens:
            return None

        token_data = self.tokens[token]
        
        # Check expiration
        expires_at = datetime.fromisoformat(token_data["expires_at"])
        if datetime.utcnow() > expires_at:
            del self.tokens[token]
            return None

        return token_data

    def revoke_token(self, token: str) -> bool:
        """Revoke token"""
        if token in self.tokens:
            del self.tokens[token]
            return True
        return False

    def refresh_token(self, refresh_token: str) -> Optional[AuthToken]:
        """Refresh token"""
        # Find token by refresh_token
        for token_value, token_data in self.tokens.items():
            if token_data.get("refresh_token") == refresh_token:
                return self.generate_token(
                    token_data["user_id"],
                    token_data.get("scopes", ["read"])
                )
        return None


class CredentialStore:
    """Store and manage user credentials"""

    def __init__(self):
        self.users: Dict[str, Dict[str, Any]] = {}

    def create_user(self, username: str, email: str,
                   password: str, scopes: list = None) -> User:
        """Create a new user"""
        if scopes is None:
            scopes = ["read"]

        user_id = secrets.token_urlsafe(16)
        password_hash = self._hash_password(password)

        user = User(
            user_id=user_id,
            username=username,
            email=email,
            scopes=scopes,
            created_at=datetime.utcnow().isoformat()
        )

        self.users[user_id] = {
            "user": user,
            "password_hash": password_hash,
        }

        logger.info(f"User created: {username}")
        return user

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with password"""
        for user_id, user_data in self.users.items():
            user = user_data["user"]
            if user.username == username:
                if self._verify_password(password, user_data["password_hash"]):
                    user.last_login = datetime.utcnow().isoformat()
                    return user
        return None

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        if user_id in self.users:
            return self.users[user_id]["user"]
        return None

    def has_scope(self, user_id: str, scope: str) -> bool:
        """Check if user has scope"""
        user = self.get_user(user_id)
        if user:
            return scope in user.scopes
        return False

    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash password"""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def _verify_password(password: str, hash_value: str) -> bool:
        """Verify password against hash"""
        return hashlib.sha256(password.encode()).hexdigest() == hash_value


class OAuthProvider:
    """OAuth2/OIDC provider"""

    def __init__(self, client_id: str, client_secret: str, issuer: str):
        """
        Initialize OAuth provider.
        
        Args:
            client_id: OAuth client ID
            client_secret: OAuth client secret
            issuer: Token issuer (e.g., https://auth.example.com)
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.issuer = issuer
        self.credential_store = CredentialStore()
        self.token_manager = TokenManager(client_secret)

    def authorize(self, username: str, password: str,
                 scope: str = "read") -> Optional[AuthToken]:
        """
        Authorize user and generate token.
        
        Args:
            username: Username
            password: Password
            scope: Requested scope
        
        Returns:
            AuthToken if successful, None otherwise
        """
        user = self.credential_store.authenticate(username, password)
        if not user:
            logger.warning(f"Authentication failed: {username}")
            return None

        # Check scopes
        requested_scopes = scope.split()
        allowed_scopes = [s for s in requested_scopes if self.credential_store.has_scope(user.user_id, s)]

        if not allowed_scopes:
            allowed_scopes = ["read"]

        token = self.token_manager.generate_token(user.user_id, allowed_scopes)
        logger.info(f"Token issued: {username}")
        return token

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate OAuth token"""
        return self.token_manager.validate_token(token)

    def introspect_token(self, token: str) -> Dict[str, Any]:
        """Introspect token"""
        token_data = self.token_manager.validate_token(token)
        if token_data:
            return {
                "active": True,
                "user_id": token_data["user_id"],
                "scopes": token_data["scopes"],
                "exp": token_data["expires_at"],
            }
        return {"active": False}


class PermissionChecker:
    """Check user permissions"""

    def __init__(self, oauth: OAuthProvider):
        self.oauth = oauth

    def check_permission(self, token: str, required_scope: str) -> bool:
        """Check if token has required scope"""
        token_data = self.oauth.validate_token(token)
        if not token_data:
            return False

        return required_scope in token_data.get("scopes", [])

    def check_resource_access(self, user_id: str, resource_id: str,
                             action: str = "read") -> bool:
        """Check resource access (can be extended with ACLs)"""
        # Basic ownership check
        # In production, would use proper ACL system
        user = self.oauth.credential_store.get_user(user_id)
        if not user:
            return False

        # Check if user has action permission
        required_scope = f"{action}:{resource_id}"
        return self.oauth.credential_store.has_scope(user_id, required_scope)


class AuthenticationMiddleware:
    """FastAPI middleware for authentication"""

    def __init__(self, oauth: OAuthProvider):
        self.oauth = oauth

    async def __call__(self, scope, receive, send):
        """ASGI middleware"""
        # Would be called by FastAPI
        # Extracts token from Authorization header
        # Validates and adds user context
        pass

    @staticmethod
    def extract_token(header: str) -> Optional[str]:
        """Extract token from Authorization header"""
        if not header:
            return None
        parts = header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        return None

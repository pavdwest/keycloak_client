"""
Keycloak Client for Multi-Tenant Litestar Infrastructure
Supports OAuth2/OIDC authentication with Organizations feature
"""

import asyncio
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import httpx
import jwt
from jwt import PyJWKClient
from functools import lru_cache


@dataclass
class KeycloakConfig:
    """Configuration for Keycloak connection"""
    server_url: str  # e.g., "https://keycloak.example.com"
    realm: str  # e.g., "multi-tenant-realm"
    client_id: str  # Client ID for this backend instance
    client_secret: str  # Client secret
    admin_client_id: Optional[str] = None  # For admin operations
    admin_client_secret: Optional[str] = None
    verify_ssl: bool = True
    token_leeway: int = 10  # seconds of leeway for token exp validation


@dataclass
class TokenInfo:
    """Decoded token information"""
    sub: str  # Subject (user ID)
    email: Optional[str]
    username: Optional[str]
    roles: List[str]
    organization_id: Optional[str]
    tenant_id: Optional[str]  # Alias for organization_id
    scopes: List[str]
    exp: int
    iat: int
    raw_token: str
    claims: Dict[str, Any]


class KeycloakError(Exception):
    """Base exception for Keycloak operations"""
    pass


class TokenValidationError(KeycloakError):
    """Token validation failed"""
    pass


class KeycloakClient:
    """
    Keycloak client for multi-tenant authentication and authorization.

    Usage for tenant backend:
        config = KeycloakConfig(
            server_url="https://keycloak.example.com",
            realm="multi-tenant-realm",
            client_id="tenant-123-backend",
            client_secret="secret"
        )
        kc = KeycloakClient(config)

        # In Litestar middleware
        token_info = await kc.validate_token(bearer_token)

    Usage for admin API:
        config = KeycloakConfig(
            server_url="https://keycloak.example.com",
            realm="multi-tenant-realm",
            client_id="admin-api",
            client_secret="admin-secret",
            admin_client_id="admin-api",
            admin_client_secret="admin-secret"
        )
        kc = KeycloakClient(config)

        # Create organization for new tenant
        org = await kc.create_organization("Acme Corp", {"tenant_id": "acme"})

        # Create client for tenant backend
        client = await kc.create_client("acme-backend", org["id"])
    """

    def __init__(self, config: KeycloakConfig):
        self.config = config
        self.base_url = f"{config.server_url}/realms/{config.realm}"
        self.admin_url = f"{config.server_url}/admin/realms/{config.realm}"

        self._jwks_client = None
        self._admin_token = None
        self._admin_token_expires = 0
        self._http_client = None
        self._token_cache: Dict[str, TokenInfo] = {}

    async def __aenter__(self):
        self._http_client = httpx.AsyncClient(verify=self.config.verify_ssl)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._http_client:
            await self._http_client.aclose()

    @property
    def http(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(verify=self.config.verify_ssl)
        return self._http_client

    @property
    def jwks_client(self) -> PyJWKClient:
        """Get or create JWKS client for token verification"""
        if self._jwks_client is None:
            jwks_uri = f"{self.base_url}/protocol/openid-connect/certs"
            self._jwks_client = PyJWKClient(jwks_uri)
        return self._jwks_client

    # =========================================================================
    # TOKEN VALIDATION (Primary use case for tenant backends)
    # =========================================================================

    async def validate_token(
        self,
        token: str,
        required_roles: Optional[List[str]] = None,
        required_scopes: Optional[List[str]] = None,
        cache_tokens: bool = True
    ) -> TokenInfo:
        """
        Validate a JWT bearer token from Authorization header.

        Args:
            token: JWT token string (without "Bearer " prefix)
            required_roles: List of roles user must have
            required_scopes: List of scopes token must have
            cache_tokens: Whether to cache decoded tokens

        Returns:
            TokenInfo object with user details

        Raises:
            TokenValidationError: If token is invalid or missing required claims
        """
        # Check cache first
        if cache_tokens and token in self._token_cache:
            cached = self._token_cache[token]
            if cached.exp > time.time():
                self._verify_requirements(cached, required_roles, required_scopes)
                return cached

        try:
            # Get signing key from JWKS
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            # Decode and verify token
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.config.client_id,
                issuer=f"{self.base_url}",
                leeway=self.config.token_leeway,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                }
            )

            # Extract token information
            token_info = self._parse_token_payload(payload, token)

            # Verify requirements
            self._verify_requirements(token_info, required_roles, required_scopes)

            # Cache if enabled
            if cache_tokens:
                self._token_cache[token] = token_info

            return token_info

        except jwt.ExpiredSignatureError:
            raise TokenValidationError("Token has expired")
        except jwt.InvalidAudienceError:
            raise TokenValidationError("Invalid token audience")
        except jwt.InvalidIssuerError:
            raise TokenValidationError("Invalid token issuer")
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(f"Invalid token: {str(e)}")
        except Exception as e:
            raise TokenValidationError(f"Token validation failed: {str(e)}")

    def _parse_token_payload(self, payload: Dict[str, Any], raw_token: str) -> TokenInfo:
        """Parse JWT payload into TokenInfo"""
        # Extract roles from realm_access and resource_access
        roles = []
        if "realm_access" in payload:
            roles.extend(payload["realm_access"].get("roles", []))
        if "resource_access" in payload and self.config.client_id in payload["resource_access"]:
            roles.extend(payload["resource_access"][self.config.client_id].get("roles", []))

        # Extract scopes
        scopes = payload.get("scope", "").split() if "scope" in payload else []

        # Extract organization/tenant ID (from custom claims)
        org_id = payload.get("organization_id") or payload.get("org_id")
        tenant_id = payload.get("tenant_id") or org_id

        return TokenInfo(
            sub=payload["sub"],
            email=payload.get("email"),
            username=payload.get("preferred_username"),
            roles=roles,
            organization_id=org_id,
            tenant_id=tenant_id,
            scopes=scopes,
            exp=payload["exp"],
            iat=payload["iat"],
            raw_token=raw_token,
            claims=payload
        )

    def _verify_requirements(
        self,
        token_info: TokenInfo,
        required_roles: Optional[List[str]],
        required_scopes: Optional[List[str]]
    ):
        """Verify token meets role and scope requirements"""
        if required_roles:
            token_roles = set(token_info.roles)
            missing_roles = set(required_roles) - token_roles
            if missing_roles:
                raise TokenValidationError(
                    f"Missing required roles: {', '.join(missing_roles)}"
                )

        if required_scopes:
            token_scopes = set(token_info.scopes)
            missing_scopes = set(required_scopes) - token_scopes
            if missing_scopes:
                raise TokenValidationError(
                    f"Missing required scopes: {', '.join(missing_scopes)}"
                )

    # =========================================================================
    # TOKEN INTROSPECTION (Alternative validation method)
    # =========================================================================

    async def introspect_token(self, token: str) -> Dict[str, Any]:
        """
        Introspect a token using Keycloak's introspection endpoint.
        This is slower than JWT validation but works for opaque tokens.
        """
        url = f"{self.base_url}/protocol/openid-connect/token/introspect"

        response = await self.http.post(
            url,
            data={
                "token": token,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
            }
        )

        if response.status_code != 200:
            raise KeycloakError(f"Token introspection failed: {response.text}")

        result = response.json()
        if not result.get("active"):
            raise TokenValidationError("Token is not active")

        return result

    # =========================================================================
    # ADMIN OPERATIONS (For admin API)
    # =========================================================================

    async def _get_admin_token(self) -> str:
        """Get admin access token (cached)"""
        if self._admin_token and time.time() < self._admin_token_expires - 30:
            return self._admin_token

        if not self.config.admin_client_id or not self.config.admin_client_secret:
            raise KeycloakError("Admin credentials not configured")

        url = f"{self.base_url}/protocol/openid-connect/token"

        response = await self.http.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.config.admin_client_id,
                "client_secret": self.config.admin_client_secret,
            }
        )

        if response.status_code != 200:
            raise KeycloakError(f"Failed to get admin token: {response.text}")

        data = response.json()
        self._admin_token = data["access_token"]
        self._admin_token_expires = time.time() + data["expires_in"]

        return self._admin_token

    async def _admin_request(
        self,
        method: str,
        path: str,
        **kwargs
    ) -> httpx.Response:
        """Make an authenticated admin API request"""
        token = await self._get_admin_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"

        url = f"{self.admin_url}{path}"
        response = await self.http.request(method, url, headers=headers, **kwargs)

        return response

    # =========================================================================
    # ORGANIZATION MANAGEMENT
    # =========================================================================

    async def create_organization(
        self,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
        domains: Optional[List[str]] = None,
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new organization (tenant).

        Args:
            name: Organization name (required)
            attributes: Custom attributes as key-value pairs (e.g., {"tenant_id": ["acme"]})
                       Note: Values must be lists of strings
            domains: List of internet domains for the organization
            description: Organization description

        Returns:
            Organization details including id
        """
        # Build the OrganizationRepresentation payload
        payload = {
            "name": name,
            "enabled": True,
        }

        # Add optional fields
        if description:
            payload["description"] = description

        if domains:
            payload["domains"] = [{"name": domain, "verified": False} for domain in domains]

        # Attributes must be in the format: key -> list of strings
        if attributes:
            formatted_attrs = {}
            for key, value in attributes.items():
                # Ensure values are lists
                if isinstance(value, list):
                    formatted_attrs[key] = value
                else:
                    formatted_attrs[key] = [str(value)]
            payload["attributes"] = formatted_attrs

        response = await self._admin_request(
            "POST",
            "/organizations",
            json=payload
        )

        if response.status_code not in (201, 200):
            raise KeycloakError(f"Failed to create organization: {response.text}")

        # Get organization ID from Location header or response body
        location = response.headers.get("Location", "")
        if location:
            org_id = location.split("/")[-1]
            # Fetch full organization details
            return await self.get_organization(org_id)
        else:
            # Some Keycloak versions might return the org in the body
            try:
                return response.json()
            except:
                raise KeycloakError("Failed to get organization ID from response")

    async def get_organization(self, org_id: str) -> Dict[str, Any]:
        """Get organization details"""
        response = await self._admin_request("GET", f"/organizations/{org_id}")

        if response.status_code != 200:
            raise KeycloakError(f"Failed to get organization: {response.text}")

        return response.json()

    async def list_organizations(self) -> List[Dict[str, Any]]:
        """List all organizations"""
        response = await self._admin_request("GET", "/organizations")

        if response.status_code != 200:
            raise KeycloakError(f"Failed to list organizations: {response.text}")

        return response.json()

    async def delete_organization(self, org_id: str):
        """Delete an organization"""
        response = await self._admin_request("DELETE", f"/organizations/{org_id}")

        if response.status_code != 204:
            raise KeycloakError(f"Failed to delete organization: {response.text}")

    # =========================================================================
    # CLIENT MANAGEMENT
    # =========================================================================

    async def create_client(
        self,
        client_id: str,
        organization_id: Optional[str] = None,
        redirect_uris: Optional[List[str]] = None,
        web_origins: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Create a new OAuth2/OIDC client for a tenant backend.

        Args:
            client_id: Client identifier (e.g., "acme-backend")
            organization_id: Organization to associate with
            redirect_uris: Allowed redirect URIs
            web_origins: Allowed CORS origins

        Returns:
            Client details with generated secret
        """
        payload = {
            "clientId": client_id,
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "authorizationServicesEnabled": False,
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": True,
            "redirectUris": redirect_uris or ["*"],
            "webOrigins": web_origins or ["*"],
            "attributes": {}
        }

        if organization_id:
            payload["attributes"]["organization_id"] = organization_id

        response = await self._admin_request(
            "POST",
            "/clients",
            json=payload
        )

        if response.status_code not in (201, 200):
            raise KeycloakError(f"Failed to create client: {response.text}")

        # Get client details including secret
        clients = await self.list_clients(client_id=client_id)
        if not clients:
            raise KeycloakError("Client created but not found")

        client = clients[0]
        secret = await self.get_client_secret(client["id"])
        client["secret"] = secret

        return client

    async def list_clients(self, client_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List clients"""
        params = {}
        if client_id:
            params["clientId"] = client_id

        response = await self._admin_request("GET", "/clients", params=params)

        if response.status_code != 200:
            raise KeycloakError(f"Failed to list clients: {response.text}")

        return response.json()

    async def get_client_secret(self, client_uuid: str) -> str:
        """Get client secret"""
        response = await self._admin_request(
            "GET",
            f"/clients/{client_uuid}/client-secret"
        )

        if response.status_code != 200:
            raise KeycloakError(f"Failed to get client secret: {response.text}")

        return response.json()["value"]

    async def delete_client(self, client_uuid: str):
        """Delete a client"""
        response = await self._admin_request("DELETE", f"/clients/{client_uuid}")

        if response.status_code != 204:
            raise KeycloakError(f"Failed to delete client: {response.text}")

    # =========================================================================
    # USER MANAGEMENT
    # =========================================================================

    async def create_user(
        self,
        username: str,
        email: str,
        first_name: str,
        last_name: str,
        organization_id: Optional[str] = None,
        enabled: bool = True,
        email_verified: bool = False
    ) -> Dict[str, Any]:
        """Create a new user"""
        payload = {
            "username": username,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": enabled,
            "emailVerified": email_verified,
        }

        # Add attributes if organization_id provided
        # Attributes must be key -> list of strings format
        if organization_id:
            payload["attributes"] = {
                "organization_id": [organization_id]
            }

        response = await self._admin_request(
            "POST",
            "/users",
            json=payload
        )

        if response.status_code not in (201, 200):
            raise KeycloakError(f"Failed to create user: {response.text}")

        user_id = response.headers.get("Location", "").split("/")[-1]
        return await self.get_user(user_id)

    async def get_user(self, user_id: str) -> Dict[str, Any]:
        """Get user details"""
        response = await self._admin_request("GET", f"/users/{user_id}")

        if response.status_code != 200:
            raise KeycloakError(f"Failed to get user: {response.text}")

        return response.json()

    async def list_users(
        self,
        organization_id: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List users"""
        params = {}
        if search:
            params["search"] = search

        response = await self._admin_request("GET", "/users", params=params)

        if response.status_code != 200:
            raise KeycloakError(f"Failed to list users: {response.text}")

        users = response.json()

        # Filter by organization if specified
        if organization_id:
            users = [
                u for u in users
                if organization_id in u.get("attributes", {}).get("organization_id", [])
            ]

        return users

    async def delete_user(self, user_id: str):
        """Delete a user"""
        response = await self._admin_request("DELETE", f"/users/{user_id}")

        if response.status_code != 204:
            raise KeycloakError(f"Failed to delete user: {response.text}")

    async def set_user_password(
        self,
        user_id: str,
        password: str,
        temporary: bool = False
    ):
        """Set user password"""
        payload = {
            "type": "password",
            "value": password,
            "temporary": temporary
        }

        response = await self._admin_request(
            "PUT",
            f"/users/{user_id}/reset-password",
            json=payload
        )

        if response.status_code != 204:
            raise KeycloakError(f"Failed to set password: {response.text}")

    # =========================================================================
    # ROLE MANAGEMENT
    # =========================================================================

    async def assign_realm_role_to_user(self, user_id: str, role_name: str):
        """Assign a realm role to a user"""
        # Get role details
        role = await self._get_realm_role(role_name)

        response = await self._admin_request(
            "POST",
            f"/users/{user_id}/role-mappings/realm",
            json=[role]
        )

        if response.status_code not in (204, 200):
            raise KeycloakError(f"Failed to assign role: {response.text}")

    async def _get_realm_role(self, role_name: str) -> Dict[str, Any]:
        """Get realm role details"""
        response = await self._admin_request("GET", f"/roles/{role_name}")

        if response.status_code != 200:
            raise KeycloakError(f"Failed to get role: {response.text}")

        return response.json()

    # =========================================================================
    # WELLKNOWN / DISCOVERY
    # =========================================================================

    async def get_wellknown_config(self) -> Dict[str, Any]:
        """Get OpenID Connect discovery configuration"""
        url = f"{self.base_url}/.well-known/openid-configuration"
        response = await self.http.get(url)

        if response.status_code != 200:
            raise KeycloakError(f"Failed to get wellknown config: {response.text}")

        return response.json()

    async def get_auth_url(
        self,
        redirect_uri: str,
        state: Optional[str] = None,
        scope: str = "openid profile email"
    ) -> str:
        """Generate authorization URL for OAuth2 flow"""
        config = await self.get_wellknown_config()
        auth_endpoint = config["authorization_endpoint"]

        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
        }

        if state:
            params["state"] = state

        query_string = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{auth_endpoint}?{query_string}"

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for access token"""
        url = f"{self.base_url}/protocol/openid-connect/token"

        response = await self.http.post(
            url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
            }
        )

        if response.status_code != 200:
            raise KeycloakError(f"Failed to exchange code: {response.text}")

        return response.json()


# =============================================================================
# LITESTAR INTEGRATION
# =============================================================================

class KeycloakAuthMiddleware:
    """
    Litestar middleware for Keycloak authentication.

    Usage in Litestar app:

        from litestar import Litestar, Request, get
        from litestar.middleware import DefineMiddleware

        keycloak_config = KeycloakConfig(
            server_url="https://keycloak.example.com",
            realm="multi-tenant-realm",
            client_id="tenant-123-backend",
            client_secret="secret"
        )

        auth_middleware = DefineMiddleware(
            KeycloakAuthMiddleware,
            config=keycloak_config,
            excluded_paths=["/health", "/docs"]
        )

        @get("/protected")
        async def protected_route(request: Request) -> dict:
            # Access token info from request state
            token_info: TokenInfo = request.state.token_info
            return {"user_id": token_info.sub, "tenant": token_info.tenant_id}

        app = Litestar(
            route_handlers=[protected_route],
            middleware=[auth_middleware]
        )
    """

    def __init__(
        self,
        app,
        config: KeycloakConfig,
        excluded_paths: Optional[List[str]] = None,
        required_roles: Optional[List[str]] = None,
        required_scopes: Optional[List[str]] = None
    ):
        self.app = app
        self.client = KeycloakClient(config)
        self.excluded_paths = excluded_paths or []
        self.required_roles = required_roles
        self.required_scopes = required_scopes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope["path"]

        # Skip authentication for excluded paths
        if any(path.startswith(excluded) for excluded in self.excluded_paths):
            await self.app(scope, receive, send)
            return

        # Extract bearer token
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode()

        if not auth_header.startswith("Bearer "):
            await self._send_unauthorized(send, "Missing or invalid Authorization header")
            return

        token = auth_header[7:]  # Remove "Bearer " prefix

        try:
            # Validate token
            token_info = await self.client.validate_token(
                token,
                required_roles=self.required_roles,
                required_scopes=self.required_scopes
            )

            # Store token info in request state
            scope["state"] = scope.get("state", {})
            scope["state"]["token_info"] = token_info

            await self.app(scope, receive, send)

        except TokenValidationError as e:
            await self._send_unauthorized(send, str(e))

    async def _send_unauthorized(self, send, message: str):
        """Send 401 Unauthorized response"""
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [[b"content-type", b"application/json"]],
        })
        await send({
            "type": "http.response.body",
            "body": f'{{"detail": "{message}"}}'.encode(),
        })


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def extract_token_from_header(authorization: str) -> str:
    """Extract bearer token from Authorization header.
    
    Args:
        authorization: The Authorization header value (e.g., 'Bearer token123')
        
    Returns:
        The extracted token
        
    Raises:
        ValueError: If the authorization header is invalid
    """
    if not authorization or not isinstance(authorization, str):
        raise ValueError("Invalid Authorization header format")
        
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise ValueError("Invalid Authorization header format")
        
    return parts[1]

async def create_tenant_infrastructure(
    admin_client: KeycloakClient,
    tenant_name: str,
    tenant_id: str,
    backend_redirect_uris: List[str]
) -> Dict[str, Any]:
    """
    Complete setup for a new tenant: organization + client.

    Returns dict with organization and client details.
    """
    # Create organization - attributes values must be lists
    org = await admin_client.create_organization(
        name=tenant_name,
        attributes={"tenant_id": [tenant_id]}  # Must be a list!
    )

    # Create client for backend
    client = await admin_client.create_client(
        client_id=f"{tenant_id}-backend",
        organization_id=org["id"],
        redirect_uris=backend_redirect_uris
    )

    return {
        "organization": org,
        "client": client,
        "client_id": client["clientId"],
        "client_secret": client["secret"]
    }

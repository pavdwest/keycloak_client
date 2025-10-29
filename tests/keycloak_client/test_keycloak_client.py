"""Unit tests for the Keycloak client."""
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, ANY
import pytest
import jwt
import httpx

from keycloak_client.keycloak_client import (
    KeycloakClient,
    KeycloakConfig,
    TokenInfo,
    TokenValidationError,
    KeycloakError
)


class TestKeycloakConfig:
    """Tests for KeycloakConfig dataclass."""

    def test_keycloak_config_initialization(self):
        """Test that KeycloakConfig is initialized correctly."""
        config = KeycloakConfig(
            server_url="https://keycloak.example.com",
            realm="test-realm",
            client_id="test-client",
            client_secret="test-secret"
        )

        assert config.server_url == "https://keycloak.example.com"
        assert config.realm == "test-realm"
        assert config.client_id == "test-client"
        assert config.client_secret == "test-secret"
        assert config.admin_client_id is None
        assert config.admin_client_secret is None
        assert config.verify_ssl is True
        assert config.token_leeway == 10


class TestTokenInfo:
    """Tests for TokenInfo dataclass."""

    def test_token_info_initialization(self):
        """Test that TokenInfo is initialized correctly."""
        now = int(time.time())
        token_info = TokenInfo(
            sub="12345",
            email="test@example.com",
            username="testuser",
            roles=["user", "admin"],
            organization_id="org-123",
            tenant_id="org-123",
            scopes=["openid", "email", "profile"],
            exp=now + 3600,
            iat=now,
            raw_token="test.token.123",
            claims={"sub": "12345"}
        )

        assert token_info.sub == "12345"
        assert token_info.email == "test@example.com"
        assert token_info.roles == ["user", "admin"]
        assert token_info.organization_id == "org-123"
        assert token_info.tenant_id == "org-123"
        assert token_info.scopes == ["openid", "email", "profile"]
        assert token_info.raw_token == "test.token.123"
        assert token_info.claims == {"sub": "12345"}


class TestKeycloakClient:
    """Tests for KeycloakClient class."""

    @pytest.mark.asyncio
    async def test_context_manager(self, mock_keycloak_config):
        """Test that the client can be used as an async context manager."""
        async with KeycloakClient(mock_keycloak_config) as client:
            assert isinstance(client, KeycloakClient)

    @pytest.mark.asyncio
    async def test_validate_token_success(self, keycloak_client, valid_token, valid_token_payload, mocker):
        """Test successful token validation."""
        # Mock the PyJWT decode method
        mocker.patch('jwt.decode', return_value=valid_token_payload)

        # Mock the JWKS client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "test-key"
        keycloak_client._jwks_client = MagicMock()
        keycloak_client._jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        # Call the method
        token_info = await keycloak_client.validate_token(valid_token)

        # Assertions
        assert token_info.sub == valid_token_payload["sub"]
        assert token_info.email == valid_token_payload["email"]
        assert token_info.username == valid_token_payload["preferred_username"]
        assert token_info.organization_id == valid_token_payload["organization_id"]
        assert token_info.tenant_id == valid_token_payload["organization_id"]
        assert token_info.scopes == valid_token_payload["scope"].split()

    @pytest.mark.asyncio
    async def test_validate_token_expired(self, keycloak_client, valid_token, mocker):
        """Test token validation with expired token."""
        # Mock PyJWT to raise ExpiredSignatureError
        mocker.patch('jwt.decode', side_effect=jwt.ExpiredSignatureError("Token has expired"))

        # Mock the JWKS client
        keycloak_client._jwks_client = MagicMock()

        # Assert that validation raises TokenValidationError
        with pytest.raises(TokenValidationError, match="Token has expired"):
            await keycloak_client.validate_token(valid_token)

    @pytest.mark.asyncio
    async def test_validate_token_invalid_audience(self, keycloak_client, valid_token, mocker):
        """Test token validation with invalid audience."""
        # Mock PyJWT to raise InvalidAudienceError
        mocker.patch('jwt.decode', side_effect=jwt.InvalidAudienceError("Invalid audience"))

        # Mock the JWKS client
        keycloak_client._jwks_client = MagicMock()

        # Assert that validation raises TokenValidationError
        with pytest.raises(TokenValidationError, match="Invalid token audience"):
            await keycloak_client.validate_token(valid_token)

    @pytest.mark.asyncio
    async def test_validate_token_missing_required_roles(self, keycloak_client, valid_token, valid_token_payload, mocker):
        """Test token validation with missing required roles."""
        # Mock the PyJWT decode method
        mocker.patch('jwt.decode', return_value=valid_token_payload)

        # Mock the JWKS client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "test-key"
        keycloak_client._jwks_client = MagicMock()
        keycloak_client._jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        # Test with required roles that the token doesn't have
        required_roles = ["admin", "superuser"]

        # Assert that validation raises TokenValidationError
        with pytest.raises(TokenValidationError, match="Missing required roles"):
            await keycloak_client.validate_token(
                valid_token,
                required_roles=required_roles
            )

    @pytest.mark.asyncio
    async def test_validate_token_with_required_roles(self, keycloak_client, valid_token, valid_token_payload, mocker):
        """Test token validation with required roles that the token has."""
        # Update the token payload to include required roles
        valid_token_payload["realm_access"]["roles"] = ["user", "admin"]

        # Mock the PyJWT decode method
        mocker.patch('jwt.decode', return_value=valid_token_payload)

        # Mock the JWKS client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "test-key"
        keycloak_client._jwks_client = MagicMock()
        keycloak_client._jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        # Test with required roles that the token has
        required_roles = ["admin"]

        # This should not raise an exception
        token_info = await keycloak_client.validate_token(
            valid_token,
            required_roles=required_roles
        )

        assert token_info is not None
        assert "admin" in token_info.roles

    @pytest.mark.asyncio
    async def test_validate_token_caching(self, keycloak_client, valid_token, valid_token_payload, mocker):
        """Test that token validation results are cached."""
        # Mock the PyJWT decode method
        mocker.patch('jwt.decode', return_value=valid_token_payload)

        # Mock the JWKS client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "test-key"
        keycloak_client._jwks_client = MagicMock()
        keycloak_client._jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        # First call - should call decode
        await keycloak_client.validate_token(valid_token, cache_tokens=True)

        # Reset the mock to track subsequent calls
        jwt.decode.reset_mock()

        # Second call with same token - should use cache
        await keycloak_client.validate_token(valid_token, cache_tokens=True)

        # Verify decode was not called again
        jwt.decode.assert_not_called()

    @pytest.mark.asyncio
    async def test_validate_token_cache_expired(self, keycloak_client, valid_token, valid_token_payload, mocker):
        """Test that expired tokens are not served from cache."""
        # Set token to be expired
        valid_token_payload["exp"] = int(time.time()) - 100

        # Create a mock for the JWKS client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "test-key"
        keycloak_client._jwks_client = MagicMock()
        keycloak_client._jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        # Mock the JWT decode to raise ExpiredSignatureError
        mocker.patch('jwt.decode', side_effect=jwt.ExpiredSignatureError("Token has expired"))

        # Add to cache
        keycloak_client._token_cache[valid_token] = TokenInfo(
            sub=valid_token_payload["sub"],
            email=valid_token_payload["email"],
            username=valid_token_payload["preferred_username"],
            roles=[],
            organization_id=valid_token_payload["organization_id"],
            tenant_id=valid_token_payload["organization_id"],
            scopes=valid_token_payload["scope"].split(),
            exp=valid_token_payload["exp"],
            iat=valid_token_payload["iat"],
            raw_token=valid_token,
            claims=valid_token_payload
        )

        # Should raise expired token error
        with pytest.raises(TokenValidationError, match="Token has expired"):
            await keycloak_client.validate_token(valid_token, cache_tokens=True)


class TestKeycloakAuthMiddleware:
    """Tests for KeycloakAuthMiddleware."""

    @pytest.mark.asyncio
    async def test_middleware_excluded_path(self, mock_keycloak_config):
        """Test that excluded paths bypass authentication."""
        from keycloak_client.keycloak_client import KeycloakAuthMiddleware

        # Create an awaitable mock
        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        # Create middleware with excluded path
        middleware = KeycloakAuthMiddleware(
            mock_app,
            config=mock_keycloak_config,
            excluded_paths=["/health"]
        )

        # Mock ASGI call
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/health",
            "headers": []
        }

        receive = AsyncMock()
        send = AsyncMock()

        # Call the middleware
        await middleware(scope, receive, send)

        # Verify the app was called
        assert app_called is True

    @pytest.mark.asyncio
    async def test_middleware_missing_auth_header(self, mock_keycloak_config):
        """Test that missing Authorization header returns 401."""
        from keycloak_client.keycloak_client import KeycloakAuthMiddleware

        # Create middleware with a mock app (shouldn't be called)
        app_called = False

        async def mock_app(scope, receive, send):
            nonlocal app_called
            app_called = True
            assert False, "App should not be called for unauthorized requests"

        middleware = KeycloakAuthMiddleware(mock_app, config=mock_keycloak_config)

        # Mock ASGI call without Authorization header
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/protected",
            "headers": []
        }

        receive = AsyncMock()
        send = AsyncMock()

        # Call the middleware
        await middleware(scope, receive, send)

        # Verify app was not called
        assert app_called is False

        # Verify 401 Unauthorized was sent
        send_calls = [call[0][0] for call in send.await_args_list]
        assert any(call.get('type') == 'http.response.start' and
                 call.get('status') == 401
                 for call in send_calls)


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_extract_token_from_header(self):
        """Test token extraction from Authorization header."""
        from keycloak_client.keycloak_client import extract_token_from_header

        # Test with Bearer token
        auth_header = "Bearer test.token.123"
        assert extract_token_from_header(auth_header) == "test.token.123"

        # Test with lowercase bearer
        auth_header = "bearer test.token.123"
        assert extract_token_from_header(auth_header) == "test.token.123"

        # Test with missing token
        with pytest.raises(ValueError, match="Invalid Authorization header format"):
            extract_token_from_header("Bearer")

        # Test with invalid prefix
        with pytest.raises(ValueError, match="Invalid Authorization header format"):
            extract_token_from_header("Basic dXNlcjpwYXNz")

        # Test with None
        with pytest.raises(ValueError, match="Invalid Authorization header format"):
            extract_token_from_header(None)

        # Test with empty string
        with pytest.raises(ValueError, match="Invalid Authorization header format"):
            extract_token_from_header("")

        # Test with multiple spaces
        assert extract_token_from_header("Bearer    test.token.123") == "test.token.123"


class TestTokenParsing:
    """Test token parsing functionality."""

    def test_parse_token_minimal_payload(self, keycloak_client):
        """Test parsing token with minimal required fields."""
        payload = {
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        token_info = keycloak_client._parse_token_payload(payload, "raw.token")
        assert token_info.sub == "user-123"
        assert token_info.roles == []
        assert token_info.scopes == []
        assert token_info.organization_id is None
        assert token_info.tenant_id is None

    def test_parse_token_with_roles(self, keycloak_client):
        """Test parsing token with role claims."""
        payload = {
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "realm_access": {"roles": ["user", "admin"]},
            "resource_access": {"client-1": {"roles": ["client-role"]}},
            "organization_id": "org-123",
            "tenant_id": "tenant-123"
        }

        token_info = keycloak_client._parse_token_payload(payload, "raw.token")
        # Only realm roles should be included by default
        assert set(token_info.roles) == {"user", "admin"}
        assert token_info.organization_id == "org-123"
        assert token_info.tenant_id == "tenant-123"


class TestTokenValidationEdgeCases:
    """Test edge cases in token validation."""

    @pytest.mark.asyncio
    async def test_validate_token_empty_roles(self, keycloak_client, valid_token_payload, mocker):
        """Test token validation with empty roles."""
        payload = valid_token_payload.copy()
        payload["realm_access"] = {"roles": []}
        payload["resource_access"] = {}

        # Mock the JWKS client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "test-key"
        keycloak_client._jwks_client = MagicMock()
        keycloak_client._jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with patch('jwt.decode', return_value=payload):
            token_info = await keycloak_client.validate_token("test.token")
            assert token_info.roles == []

    @pytest.mark.asyncio
    async def test_validate_token_missing_claims(self, keycloak_client, valid_token_payload, mocker):
        """Test token validation with missing claims."""
        payload = valid_token_payload.copy()
        if "organization_id" in payload:
            del payload["organization_id"]
        if "tenant_id" in payload:
            del payload["tenant_id"]

        # Mock the JWKS client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "test-key"
        keycloak_client._jwks_client = MagicMock()
        keycloak_client._jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with patch('jwt.decode', return_value=payload):
            token_info = await keycloak_client.validate_token("test.token")
            assert token_info.organization_id is None
            assert token_info.tenant_id is None


class TestPerformance:
    """Test performance optimizations."""

    @pytest.mark.asyncio
    async def test_token_cache_performance(self, keycloak_client, valid_token_payload, mocker):
        """Test token validation caching."""
        # Mock the JWKS client
        mock_signing_key = MagicMock()
        mock_signing_key.key = "test-key"
        keycloak_client._jwks_client = MagicMock()
        keycloak_client._jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with patch('jwt.decode', return_value=valid_token_payload) as mock_decode:
            # First call - should decode
            token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.ME7gXhB5rL6vlEeqzJdQ3gXjR5Z5JzZU8U1QKvJ4V5Y"
            await keycloak_client.validate_token(token, cache_tokens=True)
            # Second call - should use cache
            await keycloak_client.validate_token(token, cache_tokens=True)
            assert mock_decode.call_count == 1

    # @pytest.mark.asyncio
    # async def test_admin_token_reuse(self, admin_keycloak_client):
    #     """Test admin token reuse across operations."""
    #     # Track the URLs that were called
    #     called_urls = []

    #     # Create a mock response
    #     mock_response = AsyncMock()
    #     mock_response.status_code = 200
    #     mock_response.json.return_value = []

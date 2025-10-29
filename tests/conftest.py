# In conftest.py, update the keycloak_client fixture:
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from keycloak_client.keycloak_client import KeycloakConfig, KeycloakClient

# Test configuration
TEST_REALM = "test-realm"
TEST_CLIENT_ID = "test-client"
TEST_CLIENT_SECRET = "test-secret"
TEST_SERVER_URL = "http://localhost:8080"

@pytest.fixture
def mock_keycloak_config():
    """Return a KeycloakConfig for testing."""
    return KeycloakConfig(
        server_url=TEST_SERVER_URL,
        realm=TEST_REALM,
        client_id=TEST_CLIENT_ID,
        client_secret=TEST_CLIENT_SECRET,
        admin_client_id="admin-cli",
        admin_client_secret="admin-secret",
        verify_ssl=False
    )

@pytest.fixture
async def keycloak_client(mock_keycloak_config):
    """Return a KeycloakClient instance for testing."""
    client = KeycloakClient(mock_keycloak_config)
    await client.__aenter__()
    yield client
    await client.__aexit__(None, None, None)

@pytest.fixture
def valid_token_payload():
    """Return a valid JWT payload for testing."""
    return {
        "sub": "1234567890",
        "email": "user@example.com",
        "preferred_username": "testuser",
        "realm_access": {"roles": ["user"]},
        "resource_access": {"account": {"roles": ["manage-account"]}},
        "organization_id": "test-org",
        "scope": "openid email profile",
        "exp": 9999999999,
        "iat": 1234567890
    }

@pytest.fixture
def valid_token():
    """Return a valid JWT token for testing."""
    return "mocked.jwt.token"


@pytest.fixture
def admin_keycloak_config():
    """Return a KeycloakConfig with admin credentials for testing."""
    return KeycloakConfig(
        server_url=TEST_SERVER_URL,
        realm=TEST_REALM,
        client_id=TEST_CLIENT_ID,
        client_secret=TEST_CLIENT_SECRET,
        admin_client_id="admin-cli",
        admin_client_secret="admin-secret",
        verify_ssl=False
    )


@pytest.fixture
async def admin_keycloak_client(admin_keycloak_config):
    """Return a KeycloakClient instance with admin credentials for testing."""
    client = KeycloakClient(admin_keycloak_config)
    await client.__aenter__()
    
    # Mock the HTTP client
    mock_http = AsyncMock()
    client._http_client = mock_http
    
    # Mock the admin token
    client._admin_token = "mock-admin-token"
    client._admin_token_expires = float('inf')
    
    yield client
    
    # Cleanup
    await client.__aexit__(None, None, None)

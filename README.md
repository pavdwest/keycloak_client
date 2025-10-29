# Overview

This is a simple project that provides an async Python Keycloak client focused on multi-tenant authentication and authorization.

This was an interesting exercise in using multiple different AIs to generate code & tests and clean it up.

## Features

- OAuth2/OIDC authentication flows
- Multi-tenant support with organizations
- User and client management
- Token validation and verification
- Admin API integration
- Litestar middleware for easy integration

## Installation

```bash
# Install from source
git clone [https://github.com/yourusername/keycloak-client.git](https://github.com/yourusername/keycloak-client.git)
cd keycloak-client
pip install -e .

# Or install directly (when published to PyPI)
# pip install keycloak-client
```

## Quick Start

### Basic Configuration

```python
from keycloak_client import KeycloakClient, KeycloakConfig

# Configure the client
config = KeycloakConfig(
    server_url="http://localhost:8080",  # Your Keycloak server URL
    realm="my-realm",                    # Your realm name
    client_id="my-client",               # Your client ID
    client_secret="your-client-secret"   # Your client secret
)

# Create a client instance
async with KeycloakClient(config) as client:
    # Your code here
    pass
```

### Validate a JWT token

```python
async def validate_user_token(token: str):
    async with KeycloakClient(config) as client:
        try:
            token_info = await client.validate_token(
                token,
                required_roles=["user"],  # Optional: require specific roles
                required_scopes=["profile"]  # Optional: require specific scopes
            )
            return token_info
        except Exception as e:
            print(f"Token validation failed: {e}")
            return None
```

### Admin Operations

```python
# Admin operations require admin credentials
admin_config = KeycloakConfig(
    server_url="http://localhost:8080",
    realm="master",  # Typically 'master' for admin operations
    client_id="admin-cli",
    client_secret="your-admin-secret"
)

async def create_tenant(tenant_name: str, tenant_id: str):
    async with KeycloakClient(admin_config) as admin_client:
        # Create organization (tenant)
        org = await admin_client.create_organization(
            name=tenant_name,
            attributes={"tenant_id": [tenant_id]}
        )

        # Create client for the tenant
        client = await admin_client.create_client(
            client_id=f"{tenant_id}-backend",
            organization_id=org["id"],
            redirect_uris=["http://localhost:8000/*"]
        )

        return {
            "organization": org,
            "client": client
        }
```


### Litestar Integration

The package includes a middleware for Litestar applications:


```python
from litestar import Litestar, get
from keycloak_client import KeycloakAuthMiddleware, KeycloakConfig

# Configure Keycloak
keycloak_config = KeycloakConfig(...)

# Create your Litestar app with Keycloak auth
app = Litestar(
    route_handlers=[...],
    middleware=[
        KeycloakAuthMiddleware,
        {
            "config": keycloak_config,
            "excluded_paths": ["/health", "/docs", "/schema"],
            "required_roles": ["user"],  # Global required roles
            "required_scopes": ["profile"]  # Global required scopes
        }
    ]
)
```

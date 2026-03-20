import os

from dotenv import load_dotenv
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl, TypeAdapter
from redis.asyncio import Redis
from starlette.requests import Request
from starlette.responses import Response

from auth.github import GitHubOAuthProvider
from tools.lta import LTAService

load_dotenv()

PORT = int(os.getenv("PORT", 8000))
SERVER_URL: AnyHttpUrl = TypeAdapter(AnyHttpUrl).validate_python(
    os.getenv("SERVER_URL", f"http://localhost:{PORT}")
)

redis = Redis.from_url(
    os.getenv("REDIS_URL", "redis://localhost:6379"),
    decode_responses=True,
    ssl_cert_reqs=None,  # DO managed Redis uses self-signed-like certs
)

github_provider = GitHubOAuthProvider(
    github_client_id=os.environ["GITHUB_CLIENT_ID"],
    github_client_secret=os.environ["GITHUB_CLIENT_SECRET"],
    server_url=str(SERVER_URL),
    redis=redis,
)

mcp = FastMCP(
    name="lta",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    port=PORT,
    auth=AuthSettings(
        issuer_url=SERVER_URL,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["read"],
            default_scopes=["read"],
        ),
        resource_server_url=SERVER_URL,
    ),
    auth_server_provider=github_provider,
)

lta_service = LTAService()


@mcp.custom_route("/github/callback", methods=["GET"])
async def github_callback(request: Request) -> Response:
    return await github_provider.handle_github_callback(request)


@mcp.tool()
async def get_bus_stops() -> str:
    """Get detailed information for all bus stops that includes:
    1. Bus stop code
    2. Road name
    3. Description to identify the bus stop
    4. Latitude and Longitude
    """
    result = await lta_service.list_bus_stops()
    return result


app = mcp.streamable_http_app()

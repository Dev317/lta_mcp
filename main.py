import os

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from tools.lta import LTAService

PORT = int(os.getenv("PORT", 8000))
mcp = FastMCP(
    name="lta",
    stateless_http=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    port=PORT,
)

lta_service = LTAService()


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

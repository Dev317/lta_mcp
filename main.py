from mcp.server.fastmcp import FastMCP

from lib.lta import LTAService

mcp = FastMCP(name="lta", stateless_http=True)

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


if __name__ == "__main__":
    mcp.run(transport="streamable-http")

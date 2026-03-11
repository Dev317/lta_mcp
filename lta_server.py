from mcp.server.fastmcp import FastMCP
from lib.lta import LTAService
import logging

mcp = FastMCP(
    name='lta',
    stateless_http=True,
    host="127.0.0.1", port=8000
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
    logging.info(f'API Result: {result}')
    return result

if __name__ == "__main__":
    mcp.run(
        transport="streamable-http"
    )

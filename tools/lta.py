import os

import httpx
from dotenv import load_dotenv
from httpx import HTTPStatusError

load_dotenv()


class LTAService:
    def __init__(self):
        self.client = httpx.AsyncClient(
            base_url="https://datamall2.mytransport.sg/ltaodataservice",
            http2=True,
            headers={"AccountKey": os.environ["LTA_DATA_MALL_API"]},
        )

    async def list_bus_stops(self) -> str:
        try:
            all_stops = []
            skip = 0
            while True:
                response = await self.client.get("/BusStops", params={"$skip": skip})
                response.raise_for_status()
                data = response.json()
                batch = data["value"]
                if not batch:
                    break
                all_stops.extend(batch)
                skip += 500

            formatted_result = "\n".join(
                [
                    f"""
                    Bus stop code: {bus_stop["BusStopCode"]}
                    Road name: {bus_stop["RoadName"]}
                    Description: {bus_stop["Description"]}
                    Latitude: {bus_stop["Latitude"]}
                    Longitude: {bus_stop["Longitude"]}
                    """
                    for bus_stop in all_stops
                ]
            )

            return formatted_result
        except HTTPStatusError:
            return ""

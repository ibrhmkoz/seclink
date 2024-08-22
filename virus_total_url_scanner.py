import asyncio
import aiohttp
import ssl
import certifi


class VirusTotalScanner:
    def __init__(self, api_key):
        self._api_key = api_key
        self._scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
        self._report_url = 'https://www.virustotal.com/vtapi/v2/url/report'

    async def scan_url(self, url):
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
            scan_params = {'apikey': self._api_key, 'url': url}
            async with session.post(self._scan_url, data=scan_params) as response:
                scan_result = await response.json()

            scan_id = scan_result.get('scan_id')
            if not scan_id:
                raise ValueError(f"Failed to get scan_id. Response: {scan_result}")

            return await self.poll_result(session, scan_id)

    async def poll_result(self, session, scan_id):
        max_tries = 10
        base_wait_time = 1

        for attempt in range(max_tries):
            report_params = {'apikey': self._api_key, 'resource': scan_id}
            async with session.get(self._report_url, params=report_params) as response:
                report_result = await response.json()

            if report_result.get('response_code') == 1:  # Result is ready
                return report_result

            # If result not ready, wait before trying again
            wait_time = base_wait_time * (2 ** attempt)  # Exponential backoff
            print(f"Result not ready. Waiting {wait_time} seconds before retrying...")
            await asyncio.sleep(wait_time)

        raise TimeoutError("Max retries reached. Scan result not available.")


async def main():
    api_key = ''
    url_to_scan = 'https://stackoverflow.com/'

    scanner = VirusTotalScanner(api_key)
    try:
        result = await scanner.scan_url(url_to_scan)
        print(result)
    except (TimeoutError, ValueError, aiohttp.ClientError) as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())

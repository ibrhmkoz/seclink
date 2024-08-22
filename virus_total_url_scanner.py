import asyncio
import aiohttp
import ssl
import certifi


class VirusTotalURLScanner:
    def __init__(self, api_key):
        self._api_key = api_key
        self._base_url = 'https://www.virustotal.com/api/v3'
        self._headers = {
            'x-apikey': self._api_key,
            'Accept': 'application/json'
        }

    async def scan_url(self, url):
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
            scan_data = {'url': url}
            async with session.post(f'{self._base_url}/urls', headers=self._headers, data=scan_data) as response:
                scan_result = await response.json()

            analysis_id = scan_result.get('data', {}).get('id')
            if not analysis_id:
                raise ValueError(f"Failed to get analysis_id. Response: {scan_result}")

            return await self.poll_result(session, analysis_id)

    async def poll_result(self, session, analysis_id):
        max_tries = 10
        base_wait_time = 1

        for attempt in range(max_tries):
            async with session.get(f'{self._base_url}/analyses/{analysis_id}', headers=self._headers) as response:
                report_result = await response.json()

            status = report_result.get('data', {}).get('attributes', {}).get('status')
            if status == 'completed':
                return report_result

            # If result not ready, wait before trying again
            wait_time = base_wait_time * (2 ** attempt)  # Exponential backoff
            print(f"Result not ready. Waiting {wait_time} seconds before retrying...")
            await asyncio.sleep(wait_time)

        raise TimeoutError("Max retries reached. Scan result not available.")


async def main():
    api_key = ''
    url_to_scan = 'https://stackoverflow.com/'

    scanner = VirusTotalURLScanner(api_key)
    try:
        result = await scanner.scan_url(url_to_scan)
        print(result)
    except (TimeoutError, ValueError, aiohttp.ClientError) as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())

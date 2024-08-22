import asyncio
import aiohttp
import ssl
import certifi

from retry import retry_with_exponential_backoff


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

            return await retry_with_exponential_backoff(lambda: self.get_analysis_result(session, analysis_id))

    async def get_analysis_result(self, session, analysis_id):
        async with session.get(f'{self._base_url}/analyses/{analysis_id}', headers=self._headers) as response:
            report_result = await response.json()

        status = report_result.get('data', {}).get('attributes', {}).get('status')
        if status == 'completed':
            return report_result
        else:
            raise TimeoutError("Analysis not completed yet")


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

import asyncio

from extract_links import extract_links


def format_to_tabular_form(links, results):
    formatted_results = []

    for link, result in zip(links, results):
        formatted_results.append(dict(link, **result["data"]["attributes"]["stats"]))

    return formatted_results


# VirusTotalThoroughScanner scans a URL and its direct links, aggregates the results, and returns them.
class VirusTotalThoroughScanner:
    def __init__(self, scanner):
        self.scanner = scanner

    async def scan_url(self, url):
        # Create a list of dictionaries with link and result
        links = extract_links(url)

        # Create a list of coroutines
        scan_tasks = [self.scanner.scan_url(link) for link in links]

        # Run all scan tasks concurrently
        results = await asyncio.gather(*scan_tasks)

        # Create a list of dictionaries with link and result
        formatted_results = [{"link": link, "result": result} for link, result in zip(links, results)]

        return formatted_results

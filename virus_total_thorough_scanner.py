import asyncio

from extract_links import extract_links


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
        tabular_form = format_to_tabular_form(links, results)

        return tabular_form


def format_to_tabular_form(links, results):
    formatted_results = []

    for link, result in zip(links, results):
        d = {"link": link} | result["data"]["attributes"]["stats"]
        formatted_results.append(d)

    return formatted_results


class StubScanner:
    async def scan_url(self, url):
        return [
            {"malicious": 2, "suspicious": 6, "undetected": 1, "timeout": 0, "link": "foo.com"},
            {"malicious": 4, "suspicious": 3, "undetected": 2, "timeout": 7, "link": "boo.com"}
        ]

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def extract_links(url):
    response = requests.get(url)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, 'html.parser')
    links = set()
    links.add(url)

    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()

        # Skip JavaScript links
        if href.startswith('javascript:'):
            continue

        # Convert relative URLs to absolute URLs
        href = urljoin(url, href)

        # Parse the URL to handle fragment identifiers
        parsed_url = urlparse(href)
        if parsed_url.scheme and parsed_url.netloc:
            # Skip pure fragment identifiers (e.g., # or #content)
            if parsed_url.path or parsed_url.query:
                links.add(href)

    return links

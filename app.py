import asyncio

from flask import Flask, Blueprint, request, jsonify
from flask.views import MethodView

from extract_links import extract_links
from virus_total_url_scanner import VirusTotalURLScanner

app = Flask(__name__)
v1 = Blueprint('v1', __name__, url_prefix='/api/v1')


class ScannerView(MethodView):
    def __init__(self, scanner):
        self.scanner = scanner

    async def post(self):
        data = request.json
        if not data or 'url' not in data:
            return jsonify({"error": "URL not provided in the payload"}), 400

        url = data['url']
        links = extract_links(url)

        # Create a list of coroutines
        scan_tasks = [self.scanner.scan_url(link) for link in links]

        # Run all scan tasks concurrently
        results = await asyncio.gather(*scan_tasks)

        # Create a list of dictionaries with link and result
        formatted_results = [{"link": link, "result": result} for link, result in zip(links, results)]

        return jsonify({"results": formatted_results})


VIRUS_TOTAL_API_KEY = '22d7b8b2228b98184fc9416de2a51bae89d987dbcd6d3f56ac1992616c7156a2'
scanner_view = ScannerView.as_view('scanner', VirusTotalURLScanner(VIRUS_TOTAL_API_KEY))
v1.add_url_rule('/scan', view_func=scanner_view)

if __name__ == "__main__":
    app.register_blueprint(v1)
    app.run(host="0.0.0.0", port=8000, debug=True)

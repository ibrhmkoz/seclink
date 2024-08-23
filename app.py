import asyncio
from flask import Flask, Blueprint, request, jsonify
from flask.views import MethodView

from virus_total_thorough_scanner import VirusTotalThoroughScanner
from virus_total_url_scanner import VirusTotalURLScanner, CachedScanner

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

        return await self.scanner.scan_url(url)


VIRUS_TOTAL_API_KEY = '22d7b8b2228b98184fc9416de2a51bae89d987dbcd6d3f56ac1992616c7156a2'

scan_result_summarizer = VirusTotalThoroughScanner(CachedScanner(VirusTotalURLScanner(VIRUS_TOTAL_API_KEY)))
scanner_view = ScannerView.as_view('scanner', scan_result_summarizer)
v1.add_url_rule('/scan', view_func=scanner_view)

if __name__ == "__main__":
    app.register_blueprint(v1)
    app.run(host="0.0.0.0", port=8000, debug=True)

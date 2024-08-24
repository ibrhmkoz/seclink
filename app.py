from flask import Flask, request, jsonify, render_template
from flask.views import MethodView

from virus_total_thorough_scanner import VirusTotalThoroughScanner, StubScanner
from virus_total_url_scanner import VirusTotalURLScanner, CachedScanner


class ScannerView(MethodView):
    def __init__(self, scanner):
        self.scanner = scanner

    async def post(self):
        url = request.form.get('url')
        print(url)
        if url is None:
            return jsonify({'error': 'URL is required'}), 400

        result = await self.scanner.scan_url(url)

        return render_template('results.html', results=result)

    async def get(self):
        return render_template('index.html')


app = Flask(__name__)

VIRUS_TOTAL_API_KEY = '22d7b8b2228b98184fc9416de2a51bae89d987dbcd6d3f56ac1992616c7156a2'

virus_total_thorough_scanner = VirusTotalThoroughScanner(CachedScanner(VirusTotalURLScanner(VIRUS_TOTAL_API_KEY)))

stub_virus_total_thorough_scanner = StubScanner()

scanner_view = ScannerView.as_view('scanner', stub_virus_total_thorough_scanner)
app.add_url_rule('/', view_func=scanner_view)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

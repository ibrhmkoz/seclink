import asyncio

from flask import Flask, Blueprint

app = Flask(__name__)
v1 = Blueprint('v1', __name__, url_prefix='/api/v1')


async def async_get_data():
    await asyncio.sleep(1)
    return 'Done!'


@v1.route("/scan")
async def scan():
    return await async_get_data()


if __name__ == "__main__":
    app.register_blueprint(v1)
    app.run(host="0.0.0.0", port=8000, debug=True)

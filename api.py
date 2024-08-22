import asyncio

from flask import Flask

app = Flask(__name__)


async def async_get_data():
    await asyncio.sleep(1)
    return 'Done!'


@app.route("/data")
async def get_data():
    data = await async_get_data()
    return data


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

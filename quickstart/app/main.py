# ---
# title: Quickstart demo Flask app
# purpose: Minimal Flask application for Strix quickstart and Docker Compose example.
# ---
from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/")
def index():
    return jsonify({"message": "Hello from Strix quickstart!"})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Bind to all interfaces so it is reachable from Docker host
    app.run(host="0.0.0.0", port=5000)

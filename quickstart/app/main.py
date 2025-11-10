# ---
# title: Quickstart demo Flask app
# purpose: Minimal Flask application for Strix quickstart and Docker Compose example.
# ---
from __future__ import annotations
from typing import Any, Callable, cast
import flask
from flask import Flask, Response

app = Flask(__name__)

get = cast(Callable[[str], Callable[[Callable[..., Response]], Callable[..., Response]]], app.get)

jsonify: Callable[..., Response] = cast(Any, flask.jsonify)


@get("/")
def index() -> Response:
    return jsonify({"message": "Hello from Strix quickstart!"})


@get("/health")
def health() -> Response:
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Bind to all interfaces so it is reachable from Docker host
    app.run(host="0.0.0.0", port=5000)

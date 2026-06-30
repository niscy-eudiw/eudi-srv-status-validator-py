# coding: latin-1
###############################################################################
# Copyright (c) 2026 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
import json
import logging
from pathlib import Path

from flask import Flask, jsonify
from flask_swagger_ui import get_swaggerui_blueprint

from app import config


def create_app() -> Flask:
    cfg = config.load_config()

    log_cfg = cfg.get("logging", {})
    logging.basicConfig(
        level=getattr(logging, log_cfg.get("level", "INFO")),
        format=log_cfg.get(
            "format", "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
        ),
    )

    app = Flask(__name__)

    # Load swagger.json from the project root
    swagger_path = Path(__file__).parent.parent / "swagger.json"
    with swagger_path.open() as f:
        swagger_template = json.load(f)

    # Route to expose the raw spec JSON
    @app.route("/static/swagger.json")
    def swagger_spec():
        return jsonify(swagger_template)

    # Configure and register flask-swagger-ui at /swagger-ui
    SWAGGER_URL = "/swagger-ui"  # Changed endpoint path
    API_URL = "/static/swagger.json"

    swaggerui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={"app_name": "Status List Validator"},
    )

    app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

    from app.routes import bp

    app.register_blueprint(bp)

    return app

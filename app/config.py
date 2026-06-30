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
"""
Configuration loader  reads config.yaml once at startup.
"""

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


@lru_cache(maxsize=1)
def load_config(path: str | None = None) -> dict[str, Any]:
    """Load and cache the YAML configuration file."""
    # Track when the function is actually executed (cache miss)
    logger.debug("load_config called (Cache miss or first-time initialization)")

    if path:
        config_path = Path(path)
        logger.debug("Using explicitly provided config path: %s", config_path)
    else:
        env_path = os.environ.get("CONFIG_PATH")
        if env_path:
            config_path = Path(env_path)
            logger.debug(
                "Using config path from environment variable CONFIG_PATH: %s",
                config_path,
            )
        else:
            config_path = _DEFAULT_CONFIG_PATH
            logger.debug(
                "No config path provided or found in environment. Using default path: %s",
                config_path,
            )

    if not config_path.exists():
        logger.critical(
            "Configuration file absolutely does not exist at path: %s", config_path
        )
        raise FileNotFoundError(f"Config file not found: {config_path}")

    try:
        logger.info("Attempting to open and parse configuration file: %s", config_path)
        with config_path.open() as f:
            cfg = yaml.safe_load(f)

        if cfg is None:
            logger.warning(
                "Configuration file at %s is empty. Initializing with empty dictionary.",
                config_path,
            )
            cfg = {}
        elif not isinstance(cfg, dict):
            logger.error(
                "Configuration file at %s parsed as %s instead of a dictionary!",
                config_path,
                type(cfg).__name__,
            )
            raise ValueError(
                "Invalid configuration file format: Top level must be a dictionary."
            )

        logger.info(
            "Configuration successfully loaded and cached from %s. Total top-level sections: %d",
            config_path,
            len(cfg),
        )
        return cfg

    except yaml.YAMLError as e:
        logger.critical(
            "Failed to parse YAML syntax in configuration file: %s. Error: %s",
            config_path,
            e,
            exc_info=True,
        )
        raise
    except Exception as e:
        logger.critical(
            "Unexpected error while reading configuration file at %s: %s",
            config_path,
            e,
            exc_info=True,
        )
        raise


def get(section: str, key: str, default: Any = None) -> Any:
    # Note: Because load_config is decorated with @lru_cache(1), calling it here
    # will bypass parsing and pull instantly from memory after the initial boot up.
    try:
        cfg = load_config()
    except Exception as e:
        logger.error(
            "Failed to retrieve configuration key '%s.%s' because config loading failed: %s",
            section,
            key,
            e,
        )
        return default

    section_dict = cfg.get(section)
    if section_dict is None:
        logger.debug(
            "Configuration section '%s' not found. Returning default value for key '%s'.",
            section,
            key,
        )
        return default

    if not isinstance(section_dict, dict):
        logger.warning(
            "Configuration section '%s' is not a dictionary/mapping. Unable to query key '%s'.",
            section,
            key,
        )
        return default

    if key not in section_dict:
        logger.debug(
            "Configuration key '%s' not found in section '%s'. Returning default value.",
            key,
            section,
        )
        return default

    value = section_dict.get(key, default)
    logger.debug("Configuration look-up success: [%s][%s] = %s", section, key, value)
    return value

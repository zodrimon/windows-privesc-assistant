import yaml
import jsonschema
import os
import logging
from typing import Dict, Any

from privesc_assistant_win.config.schema import CONFIG_SCHEMA


import sys

def get_default_config_path() -> str:
    """Returns the absolute path to the bundled default_config.yaml."""
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # Running as PyInstaller bundle
        current_dir = os.path.join(sys._MEIPASS, "privesc_assistant_win", "config")
    else:
        # Running normally
        current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "default_config.yaml")


def load_yaml(file_path: str) -> Dict[str, Any]:
    """Loads a YAML file and returns the parsed dict."""
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def validate_config(config: Dict[str, Any]) -> None:
    """Validates the config against the JSON schema."""
    jsonschema.validate(instance=config, schema=CONFIG_SCHEMA)


def deep_update(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively updates a nested dictionary."""
    for key, value in override.items():
        if isinstance(value, dict) and key in base and isinstance(base[key], dict):
            base[key] = deep_update(base[key], value)
        else:
            base[key] = value
    return base


def load_config(user_config_path: str = None) -> Dict[str, Any]:
    """
    Loads default config, merges with user config if provided,
    and validates the final result.
    """
    default_path = get_default_config_path()
    try:
        config = load_yaml(default_path)
    except FileNotFoundError:
        logging.error(f"Default config not found at {default_path}")
        config = {}
        
    if user_config_path:
        try:
            user_config = load_yaml(user_config_path)
            config = deep_update(config, user_config)
            logging.info(f"Loaded and merged user config from {user_config_path}")
        except FileNotFoundError:
            logging.warning(f"User config file {user_config_path} not found. Proceeding with defaults.")
        except yaml.YAMLError as e:
            logging.error(f"Failed to parse user config file {user_config_path}: {e}")
            raise

    try:
        validate_config(config)
    except jsonschema.exceptions.ValidationError as e:
        logging.error(f"Configuration validation error: {e.message}")
        raise
        
    return config

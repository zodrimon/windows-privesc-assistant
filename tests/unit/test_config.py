import pytest
import jsonschema
import yaml
from unittest.mock import patch

from privesc_assistant_win.config.loader import load_config, deep_update


def test_deep_update():
    base = {"a": 1, "b": {"c": 2}}
    override = {"b": {"d": 3}, "e": 4}
    result = deep_update(base, override)
    assert result == {"a": 1, "b": {"c": 2, "d": 3}, "e": 4}


@patch("privesc_assistant_win.config.loader.get_default_config_path")
def test_load_config_default_only(mock_default, tmp_path):
    default_yaml = """
scan:
  timeout_per_check: 30
output:
  format: "terminal"
checks: ["all"]
"""
    d_path = tmp_path / "default.yaml"
    d_path.write_text(default_yaml)
    mock_default.return_value = str(d_path)
    
    config = load_config()
    assert config["scan"]["timeout_per_check"] == 30
    assert config["output"]["format"] == "terminal"


@patch("privesc_assistant_win.config.loader.get_default_config_path")
def test_load_config_with_override(mock_default, tmp_path):
    default_yaml = """
scan:
  timeout_per_check: 30
output:
  format: "terminal"
"""
    override_yaml = """
scan:
  timeout_per_check: 60
"""
    d_path = tmp_path / "default.yaml"
    d_path.write_text(default_yaml)
    mock_default.return_value = str(d_path)
    
    u_path = tmp_path / "user.yaml"
    u_path.write_text(override_yaml)
    
    config = load_config(str(u_path))
    assert config["scan"]["timeout_per_check"] == 60
    assert config["output"]["format"] == "terminal"


@patch("privesc_assistant_win.config.loader.get_default_config_path")
def test_load_config_invalid_schema(mock_default, tmp_path):
    default_yaml = """
scan:
  timeout_per_check: "invalid_string"
"""
    d_path = tmp_path / "default.yaml"
    d_path.write_text(default_yaml)
    mock_default.return_value = str(d_path)
    
    with pytest.raises(jsonschema.exceptions.ValidationError):
        load_config()


@patch("privesc_assistant_win.config.loader.get_default_config_path")
def test_load_config_malformed_yaml(mock_default, tmp_path):
    default_yaml = """
scan:
  timeout_per_check: 30
"""
    bad_yaml = "invalid: [yaml: content"
    d_path = tmp_path / "default.yaml"
    d_path.write_text(default_yaml)
    mock_default.return_value = str(d_path)
    
    u_path = tmp_path / "user.yaml"
    u_path.write_text(bad_yaml)
    
    with pytest.raises(yaml.YAMLError):
        load_config(str(u_path))

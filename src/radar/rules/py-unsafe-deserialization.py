import pickle
import yaml

def load_session(data: bytes):
    # ruleid: py-pickle-loads
    return pickle.loads(data)

def parse_config(content: str):
    # ruleid: py-yaml-unsafe-load
    return yaml.load(content)

def parse_config_v2(content: str):
    # ruleid: py-yaml-unsafe-load
    return yaml.load(content, Loader=yaml.Loader)

def parse_config_safe(content: str):
    # ok: py-yaml-unsafe-load
    return yaml.safe_load(content)

def parse_config_explicit(content: str):
    # ok: py-yaml-unsafe-load
    return yaml.load(content, Loader=yaml.SafeLoader)

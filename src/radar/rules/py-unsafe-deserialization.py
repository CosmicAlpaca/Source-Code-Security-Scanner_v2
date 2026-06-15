import pickle
import yaml

# ruleid: py-pickle-loads
def load_session(data: bytes):
    return pickle.loads(data)

# ruleid: py-yaml-unsafe-load
def parse_config(content: str):
    return yaml.load(content)

# ruleid: py-yaml-unsafe-load
def parse_config_v2(content: str):
    return yaml.load(content, Loader=yaml.Loader)

# ok: py-yaml-unsafe-load
def parse_config_safe(content: str):
    return yaml.safe_load(content)

# ok: py-yaml-unsafe-load
def parse_config_explicit(content: str):
    return yaml.load(content, Loader=yaml.SafeLoader)

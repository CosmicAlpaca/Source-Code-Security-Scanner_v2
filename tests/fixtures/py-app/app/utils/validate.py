def validate_user(payload):
    return bool(payload and payload.get("username"))


def sanitize(value):
    return str(value).replace("'", "").replace('"', "")

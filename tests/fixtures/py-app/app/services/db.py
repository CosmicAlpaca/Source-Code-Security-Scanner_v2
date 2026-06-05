from ..utils.validate import sanitize


def find_user(username):
    return _query("SELECT * FROM users WHERE name = ?", [sanitize(username)])


def remove_user(user_id):
    return _query("DELETE FROM users WHERE id = ?", [user_id])


def _query(sql, params):
    return {"sql": sql, "params": params}


class UserRepository:
    def all(self):
        return _query("SELECT * FROM users", [])

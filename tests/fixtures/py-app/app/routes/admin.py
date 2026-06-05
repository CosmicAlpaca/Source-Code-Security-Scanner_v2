from flask import Flask

from app.services.db import remove_user

app = Flask(__name__)


@app.route("/admin/users/<user_id>", methods=["DELETE", "POST"])
def delete_user(user_id):
    return remove_user(user_id)

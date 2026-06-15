from fastapi import APIRouter

from ..services.db import find_user
from ..utils.validate import validate_user

router = APIRouter()


@router.post("/api/login")
def login(payload: dict):
    if not validate_user(payload):
        return {"error": "invalid"}
    return find_user(payload["username"])


@router.get("/api/profile")
def profile(username: str):
    return find_user(username)

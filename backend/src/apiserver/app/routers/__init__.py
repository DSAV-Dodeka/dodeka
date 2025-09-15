from apiserver.app.routers.members import members_router as members
from apiserver.app.routers.admin import admin_router as admin
from apiserver.app.routers.auth import router as auth

__all__ = [
    "admin",
    "members",
    "auth"
]

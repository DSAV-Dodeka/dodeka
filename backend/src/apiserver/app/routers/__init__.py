from apiserver.app.routers.auth import router as auth_router
from apiserver.app.routers.members import members_router
from apiserver.app.routers.admin import admin_router
from apiserver.app.routers.personalrecord import personal_record_router

__all__ = [
    "auth_router",
    "members_router",
    "admin_router",
    "personal_record_router"
]

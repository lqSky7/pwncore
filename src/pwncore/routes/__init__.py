from fastapi import APIRouter

from pwncore.routes import ctf, team, auth, admin
from pwncore.config import config

# Main router (all routes go under /api)
router = APIRouter(prefix="/api")

# Include all the subroutes
router.include_router(auth.router)
router.include_router(ctf.router)
router.include_router(team.router)
if config.development:
    router.include_router(admin.router)

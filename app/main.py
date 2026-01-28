from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text

from app.core.auth_middleware import jwt_auth_middleware
from app.core.config import get_settings
from app.db.postgres import engine
from app.db.redis import close_redis, redis_client
from app.modules.auth.router import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm up connections to fail fast on misconfig
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    await redis_client.ping()

    yield

    await close_redis()
    await engine.dispose()


settings = get_settings()

app = FastAPI(title=settings.app_name, debug=settings.debug, lifespan=lifespan)
app.middleware("http")(jwt_auth_middleware)
app.include_router(auth_router)


@app.get("/health")
async def healthcheck():
    return {"status": "ok"}

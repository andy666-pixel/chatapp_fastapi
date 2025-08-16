from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from routers.user import app as user_router

app = FastAPI()

app.include_router(user_router, prefix="/users", tags=["Users"])
app.mount("/static", StaticFiles(directory="static", html=True), name="static")



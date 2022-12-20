""" authentication app"""
from fastapi import FastAPI

from .api import router

app = FastAPI(
    title="Authentication",
)


app.include_router(router)

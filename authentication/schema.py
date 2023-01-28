""" schema for authenticatin app"""

import os
from typing import Optional

from pydantic import BaseSettings


SECRET_KEY = os.getenv("SECRET_KEY")


class Settings(BaseSettings):
    """application settings"""

    SECRET_KEY: str = SECRET_KEY
    TITLE: Optional[str] = "Authentication Module"
    VERSION: Optional[str] = "0.0.1"
    DESCRIPTION: Optional[str] = "Oauth2 Implementation"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 435  # mins


settings = Settings()

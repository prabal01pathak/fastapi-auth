""" schema for authenticatin app"""

from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseSettings

load_dotenv()


class Settings(BaseSettings):
    """application settings"""

    SECRET_KEY: str = None
    TITLE: Optional[str] = "Authentication Module"
    VERSION: Optional[str] = "0.0.1"
    DESCRIPTION: Optional[str] = "Oauth2 Implementation"

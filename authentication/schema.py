""" schema for authenticatin app"""

from pydantic import BaseSettings
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    """application settings"""

    SECRET_KEY: str = None

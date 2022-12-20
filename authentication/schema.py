""" schema for authenticatin app"""

from dotenv import load_dotenv
from pydantic import BaseSettings

load_dotenv()


class Settings(BaseSettings):
    """application settings"""

    SECRET_KEY: str = None

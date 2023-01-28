""" auth utils"""

from typing import Optional
from datetime import datetime, timedelta

from fastapi import HTTPException, Request, status
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from jose import jwt

from .schema import settings


class OAuth2PasswordBearerCookie(OAuth2):
    """oauth 2 password bearer cookie class"""

    def __init__(
        self,
        tokenUrl: str,
        scheme_name: str = None,
        scopes: dict = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        header_authorization: str = request.headers.get("Authorization")
        cookie_authorization: str = request.cookies.get("Authorization")

        header_scheme, header_param = get_authorization_scheme_param(
            header_authorization
        )
        cookie_scheme, cookie_param = get_authorization_scheme_param(
            cookie_authorization
        )

        if header_scheme.lower() == "bearer":
            authorization = True
            scheme = header_scheme
            param = header_param

        elif cookie_scheme.lower() == "bearer":
            authorization = True
            scheme = cookie_scheme
            param = cookie_param

        else:
            authorization = False

        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
                )
            return None
        return param


class TokenGenerator:
    """token generator"""

    def __init__(self):
        ...

    def create_access_token_sync(
        self, data: dict, expires_mins: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    ):
        """
        The create_access_token function creates a JWT access token.
        It takes in the data dictionary and an optional expires_delta
        value, which determines when the token will expire.
        The default is 15 minutes.
        :param data:dict: Used to Pass in the data that needs to be encoded.
        :param expires_delta:Optional[timedelta]=None: Used to Set the
            expiration time of the token.
        :return: A json web token (jwt) that has been signed using the secret_key.
        :doc-author: Trelent
        """
        to_encode = data
        if not "sub" in to_encode:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="no subject found",
            )
        expire = datetime.utcnow() + timedelta(minutes=expires_mins)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(
            to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
        )
        return encoded_jwt

    async def create_access_token(
        self, data: dict, expires_mins: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    ):
        """
        The create_access_token function creates a JWT access token.
        It takes in the data dictionary and an optional expires_delta
        value, which determines when the token will expire.
        The default is 15 minutes.
        :param data:dict: Used to Pass in the data that needs to be encoded.
        :param expires_delta:Optional[timedelta]=None: Used to Set the
            expiration time of the token.
        :return: A json web token (jwt) that has been signed using the secret_key.
        :doc-author: Trelent
        """
        to_encode = data
        if not "sub" in to_encode:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="no subject found",
            )
        expire = datetime.utcnow() + timedelta(minutes=expires_mins)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(
            to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
        )
        return encoded_jwt


oauth2_scheme = OAuth2PasswordBearerCookie(tokenUrl="token")

""" authentication api"""

from datetime import datetime

from fastapi import HTTPException, status, Depends, Request, APIRouter
from fastapi.security import SecurityScopes, OAuth2PasswordRequestForm, HTTPBasic
from fastapi.responses import JSONResponse

from jose import JWTError, jwt

from .utils import oauth2_scheme
from .schema import Settings

settings = Settings()
ALGORITHM = "HS256"

router = APIRouter()


async def get_current_user(
    security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme)
):
    """
    The get_current_user function is a helper function that takes in
    a token and returns the user associated with that
    token. If no user is found, it raises an HTTPException with status
    code 401 (Unauthorized). It also raises an exception
    if there was an error decoding the token.
    :param token:str: Used to Pass the token to the function.
    :return: The username of the user that is currently logged in.
    :doc-author: Trelent

    """
    # uncomment it
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"message": "Could not validate credentials", "type": "error"},
        headers={"WWW-Authenticate": "Bearer"},
    )
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        #  validate access token time
        expire = payload.get("exp")
        if datetime.utcnow() > datetime.fromtimestamp(expire):
            raise HTTPException(
                status_code=401, detail={"message": "token has expired"}
            )
        username: str = payload.get("sub")  # replace with sub
        if username is None:
            raise credentials_exception
    except JWTError as _e:
        raise credentials_exception from _e
    scopes = payload.get("scopes", {})
    for scope in security_scopes.scopes:
        if not scopes.get(scope):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return payload


@router.post("/token")
async def get_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """set token header"""
    return {"access_token": form_data.username, "type": "bearer"}


@router.get("/")
async def read_main(request: Request):
    """
    The read_main function returns a dictionary with the
    message "Hello World" and the root_path of the request.
    The root_path is used to generate URLs for other resources.

    :param request:Request: Used to Pass the request object to the function.
    :return: A dictionary containing the message "hello world" and the root_path.

    :doc-author: Trelent
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"message": "Could not validate credentials", "type": "error"},
        headers={"WWW-Authenticate": "Basic"},
    )
    auth_header = (
        header
        if (header := request.headers.get("Authorization"))
        else request.cookies.get("Authorization")
    )
    if not auth_header:
        raise credentials_exception
    if auth_header:
        if auth_header.split(" ", maxsplit=1)[0].lower() == "basic":
            return await handle_basic_auth(request, exception=credentials_exception)
    return {"message": "server is running", "authenticated": True}


async def handle_basic_auth(request: Request, exception):
    """handle basic auth token"""
    security = HTTPBasic()
    credentials = await security(request=request)
    scopes = SecurityScopes(scopes=[])
    try:
        await get_current_user(security_scopes=scopes, token=credentials.username)
    except Exception as _e:
        print("exception while getting user data: ", _e)
        raise exception from _e
    response = JSONResponse(
        content={"message": "server is running", "authenticated": True}
    )
    response.set_cookie(
        key="Authorization", value=f"Bearer {credentials.username}", httponly=True
    )
    return response

""" authentication app"""
from fastapi import FastAPI, HTTPException, Request, Security, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware

from .api import get_current_user, handle_basic_auth, router, settings

app = FastAPI(title=settings.TITLE)

origins = ["*"]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(router)


@app.get("/")
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


@app.get("/openapi.json")
async def get_open_api_endpoint(
    current_user: dict = Security(get_current_user, scopes=["admin"])
):
    """get open api.json"""
    print("sub: ", current_user.get("sub"))
    return JSONResponse(
        get_openapi(
            title=settings.TITLE,
            version=settings.VERSION,
            routes=app.routes,
            # servers=SERVERS,
            description=settings.DESCRIPTION,
        )
    )


@app.get("/docs")
async def get_documentation(
    current_user: dict = Security(get_current_user, scopes=["admin"])
):
    """get documentation"""
    print("sub: ", current_user.get("sub"))
    return get_swagger_ui_html(openapi_url="/openapi.json", title=settings.TITLE)

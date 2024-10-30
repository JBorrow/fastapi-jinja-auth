"""
This extremely simple example shows how to use a middleware for checking
a basic authentication token set by a cookie. This is notably insecure,
and simply demonstrates the use of cookies for authentication.
"""

from typing import Annotated
from fastapi import FastAPI, Form, Request, Response, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

USERS_DATABASE = {
    "user_a": {"username": "user_a", "password": "p_a", "role": "admin"},
    "user_b": {"username": "user_b", "password": "password_b", "role": "user"},
}


def decode_payload(token):
    if "_token" not in token:
        raise RequiresLogin

    user = USERS_DATABASE.get(token.replace("_token", ""), None)

    if not user:
        raise RequiresLogin

    return user


class RequiresLogin(Exception):
    pass


app = FastAPI()

templates = Jinja2Templates(
    directory="templates",
)


@app.exception_handler(RequiresLogin)
async def login_exception_handler(request, exc):
    return RedirectResponse(url="/login")


@app.middleware("http")
async def check_token(request, call_next):
    """
    Checks the token and extracts the user from it. If
    there is no logged-in user, request.state.user is set
    to None.
    """
    try:
        token = request.cookies.get("Authorization")
        if token:
            request.state.user = decode_payload(token)
        else:
            raise RequiresLogin
    except RequiresLogin:
        request.state.user = None

    response = await call_next(request)
    return response


@app.post("/token")
async def set_token(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    response: Response,
):
    user = USERS_DATABASE.get(username)

    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    if not user["password"] == password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    new_response = RedirectResponse(url="/", status_code=302)
    new_response.set_cookie(
        key="Authorization", value=user["username"] + "_token", httponly=True
    )

    return new_response


@app.get("/login")
async def login(request: Request):
    return templates.TemplateResponse(request, "login.html")


@app.get("/protected")
async def protected(request: Request):
    if request.state.user is None:
        raise RequiresLogin
    return templates.TemplateResponse(request, "protected.html")


@app.get("/logout")
async def logout(response: Response):
    new_response = RedirectResponse(url="/login")
    new_response.delete_cookie("Authorization")
    return new_response


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(
        request, "index.html", context=dict(user=request.state.user)
    )

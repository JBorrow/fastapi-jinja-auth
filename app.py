"""
This is a slightly more complex scenario that uses JWT authentication,
though as we want to use cookies for storing the token we need to create
a couple of custom objects.

We provide _two_ main dependencies:

- get_current_user which 401s if not logged in
- get_potential_current_user which returns None if a user is not logged in.

In some cases (e.g. index.html), you want to show different content to different
users and sometimes even to users who are not logged in at all.
"""

from fastapi import FastAPI, status, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from auth import get_current_user, Token, ACCESS_TOKEN_EXPIRE_MINUTES, authenticate_user, USERS_DATABASE, create_access_token, User, get_potential_current_user
from typing import Annotated
from datetime import timedelta
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(
    directory="templates",
)


app = FastAPI()

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(USERS_DATABASE, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    new_response = RedirectResponse(url="/", status_code=302)
    new_response.set_cookie(
        key="access_token", value=access_token, httponly=True
    )
    return new_response

@app.get("/login")
async def login(request: Request):
    return templates.TemplateResponse(request, "login.html")


@app.get("/protected")
async def protected(request: Request, user: Annotated[User, Depends(get_current_user)]):
    return templates.TemplateResponse(request, "protected.html")


@app.get("/logout")
async def logout():
    new_response = RedirectResponse(url="/login")
    new_response.delete_cookie("access_token")
    return new_response


@app.get("/")
async def index(request: Request, user: Annotated[User | None, Depends(get_potential_current_user)]):
    return templates.TemplateResponse(
        request, "index.html", context=dict(user=user)
    )

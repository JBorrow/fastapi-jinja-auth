
from fastapi.security import OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.models import OAuthFlows
from fastapi import Request, status, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from typing import Annotated
import jwt

SECRET_KEY = "18be71b3d21fe674a8642ee87b382414b502fcbdfca7a3f9ce14aa8120fb3a0f"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

USERS_DATABASE = {
    "user_a": {"username": "user_a", "password": "p_a", "role": "admin"},
    "user_b": {"username": "user_b", "password": "password_b", "role": "user"},
}

class OAuth2PasswordBearerWithCookie(OAuth2):
    def __init__(
        self,
        tokenUrl: str,
        scheme_name: str = None,
        scopes: dict = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlows(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> str | None:
        authorization: str = request.cookies.get("access_token")

        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None

        return param
    
oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="/token")

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(USERS_DATABASE, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_potential_current_user(request: Request):
    try:
        token = await oauth2_scheme(request=request)
        if token:
            return await get_current_user(token)
    except HTTPException:
        return None
    
    return None




class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class User(BaseModel):
    username: str
    password: str
    role: str | None = None

def get_user(database, username: str) -> User | None:
    user_dict = database.get(username)
    if user_dict:
        return User(**user_dict)

def authenticate_user(database, username: str, password: str):
    user = get_user(database, username)
    if not user:
        return False
    if password == user.password:
        return user
    
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return f"Bearer {encoded_jwt}"


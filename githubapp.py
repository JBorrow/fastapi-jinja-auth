"""
Attempts to provide authentication through GitHub Apps.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
import httpx
import os

app = FastAPI()


templates = Jinja2Templates(
    directory="githubtemplates",
)

CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
MEMBERSHIP_REQUIRED_OF = "NOT_A_REAL_ORG"

print(CLIENT_ID)
print(CLIENT_SECRET)

@app.get("/callback")
async def github_auth_callback(code: str):
    # Exchange the code for an access token
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )

    # Extract the access token
    access_token = response.json()["access_token"]

    # Use the access token to get the user's information from the GitHub API.
    # Then use that user information to find out what groups the user is in.

    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        )

        user_info = response.json()
        print(user_info)

        response = await client.get(
            user_info["organizations_url"],
            headers={"Authorization": f"Bearer {access_token}"}
        )

        orgs = response.json()

    # Check if REQUIRED_ORG is in the list of orgs
    if any(org["login"] == MEMBERSHIP_REQUIRED_OF for org in orgs):
        print("You are a member of the required organization!")
        # Proceed with the regular login flow. Set the client cookie and move on.
        new_response = RedirectResponse(url="/", status_code=302)
        new_response.set_cookie(key="access_token", value=user_info["login"], httponly=True)
        return new_response
    else:
        print("You are not a member of the required organization.")
        raise HTTPException(
            status_code=403,
            detail="You are not a member of the required organization.",
        )


@app.get("/")
async def index(
    request: Request,
):
    user = request.cookies.get("access_token", None)
    return templates.TemplateResponse(request, "index.html", context=dict(user=user, CLIENT_ID=CLIENT_ID))


@app.get("/logout")
async def logout():
    new_response = RedirectResponse(url="/")
    new_response.delete_cookie("access_token")
    return new_response

@app.get("/protected")
async def protected(request: Request):
    # Obviously this is not secure; we did not sign this!!!
    access_token = request.cookies.get("access_token")
    if access_token is None:
        raise HTTPException(
            status_code=401,
            detail="You must be logged in to access this page.",
        )

    return templates.TemplateResponse(request, "protected.html", context=dict(user=access_token))
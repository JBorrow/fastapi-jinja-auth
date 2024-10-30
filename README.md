FastAPI Auth with Cookies
=========================

A couple of examples (one very simple, one using JWT) to do authentication
in FastAPI using cookies. Cookies are useful in this context as sometimes you
do not have complete control over the form of the HTTP requests being
sent to your API server (e.g. in the case of using jinja templates).

If you are interested in learning, I'd start with `simpleapp.py` and then
move on to `app.py` and its associated `auth.py`.

The goal of `simpleapp.py` is to introduce the concept of cookies as auth
tokens, and `app.py` makes this more concrete using JWTs.

References
----------

- https://github.com/eddyizm/HTMX_FastAPI_Login
- https://stackoverflow.com/questions/37582444/jwt-vs-cookies-for-token-based-authentication
- https://stackoverflow.com/questions/73511158/how-to-store-jwts-in-cookies-with-fastapi
- https://github.com/fastapi/fastapi/discussions/9142
- https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/#update-the-token-path-operation

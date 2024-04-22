from fastapi import Depends, HTTPException, Request

# --------------------------------------------------------------------------- #
from app.config import Config
from app.depends import DependOAuth, DependsConfig
from app.views.base import BaseView, OpenApiTags


def exclude_for_pytest(config: DependsConfig):
    if not config.auth0.use:
        raise HTTPException(
            409,
            detail="Not available in `pytest` mode.",
        )


class BrowserAuthView(BaseView):

    view_routes = {
        "get_login": {
            "url": "/login",
            "tags": [OpenApiTags.auth0],
            "name": "Login Via Auth0",
            "description": "Login using auth0 and recieve a JWT.",
        },
        "get_authorize": {
            "url": "/authorize",
            "tags": [OpenApiTags.auth0],
            "name": "Login Callback",
            "description": "Get a JSON web token.",
        },
    }

    view_router_args = dict(dependencies=[Depends(exclude_for_pytest)])

    @classmethod
    async def get_login(
        cls, config: DependsConfig, oauth: DependOAuth, request: Request
    ):

        oauth.create_client("auth0")
        url_redirect = f"{config.app.host_url}/authorize"

        return await oauth.auth0.authorize_redirect(request, url_redirect)

    @classmethod
    async def get_authorize(cls, oauth: DependOAuth, request: Request):

        print(
            oauth.auth0.client_id,
            oauth.auth0.client_secret,
        )
        token = await oauth.auth0.authorize_access_token(request)
        return token

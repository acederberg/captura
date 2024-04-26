# =========================================================================== #
import json
import secrets

import httpx
from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette.datastructures import URL
from starlette.types import Scope

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

    # NOTE: Decided to do this with httpx and redirects since I only want to
    #       implement code exchange flow (RFC 6749,
    #       see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1).
    #       Further, it is worth mentioning that I tried using ``authlib``
    #       as suggested by the quickstart but debugging token audience issues
    #       was a huge pain in the ass and it ultimately made more sense to
    #       just use httpx.
    @classmethod
    async def get_login(cls, config: DependsConfig):
        url_redirect = f"{config.app.host_url}/authorize"

        auth0 = config.auth0
        params = f"?response_type=code&client_id={auth0.app.client_id}"
        params += "&scope=openid profile email"
        params += f"&state={secrets.token_urlsafe(8)}"
        params += f"&redirect_uri={url_redirect}"
        params += f"&audience={config.auth0.api.audience}"
        url_auth0 = f"https://{config.auth0.issuer}/authorize{params}"

        return RedirectResponse(url_auth0)

    @classmethod
    async def get_authorize(
        cls,
        config: DependsConfig,
        code: str,
    ):

        response = httpx.post(
            f"https://{config.auth0.issuer}/oauth/token",
            data=dict(
                redirect_uri=f"{config.app.host_url}/authorize",
                code=code,
                grant_type="authorization_code",
                audience=config.auth0.api.audience,
                client_id=config.auth0.app.client_id,
                client_secret=config.auth0.app.client_secret.get_secret_value(),
            ),
        )

        if response.status_code != 200:
            raise HTTPException(500, detail="Failed to exchange code for token.")

        try:
            return response.json()
        except json.JSONDecodeError as err:
            raise HTTPException(
                500, detail="Failed to decode response from success"
            ) from err

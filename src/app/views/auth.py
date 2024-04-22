from fastapi import Depends, HTTPException

# --------------------------------------------------------------------------- #
from app.auth import Token
from app.depends import DependsAuth, DependsConfig
from app.views.base import BaseView, OpenApiResponseCommon, OpenApiTags


def exclude_for_auth0(config: DependsConfig):
    if config.auth0.use:
        raise HTTPException(
            409,
            detail="Not available in auth0 mode.",
        )


class PytestAuthView(BaseView):
    """This is where routes to handle login and getting tokens will be."""

    view_routes = dict(
        post_token=dict(
            url="/token",
            name="Mint Test Token",
        ),
        get_token=dict(
            url="/token",
            name="Verify Token",
        ),
    )
    view_router_args = dict(
        tags=[OpenApiTags.auth0],
        responses=OpenApiResponseCommon,
        dependencies=[Depends(exclude_for_auth0)],
    )

    @classmethod
    def post_token(cls, auth: DependsAuth, data: Token) -> str:
        """Use this to create a new token.

        This endpoint only works when authentication is in pytest mode, and
        will not use auth0 mode.
        """

        return data.try_encode(auth)

    @classmethod
    def get_token(cls, auth: DependsAuth, data: str) -> Token:
        """Use this to validate JWT payload. Decodes and returns."""

        return Token.try_decode(auth, data, header=False)

from app.auth import Token
from app.depends import DependsAuth, DependsConfig
from app.views.base import BaseView, OpenApiResponseCommon, OpenApiTags
from fastapi import HTTPException


class AuthView(BaseView):
    """This is where routes to handle login and getting tokens will be."""

    view_routes = dict(
        post_token="/token",
        get_login="/login",
        get_token="/token",
    )
    view_router_args = dict(
        tags=[OpenApiTags.auth0],
        responses=OpenApiResponseCommon,
    )

    @classmethod
    def post_token(cls, auth: DependsAuth, data: Token) -> str:
        """Use this to create a new token.

        This endpoint only works when authentication is in pytest mode, and
        will not use auth0 mode. NEVER run this application in production while
        using tokens in endpoint mode, it will allow undesired access to user
        information (because anybody could imitate any user by minting a token
        with that particular users UUID).
        """

        return data.try_encode(auth)

    @classmethod
    def get_token(cls, auth: DependsAuth, data: str) -> Token:
        return Token.try_decode(auth, data, header=False)

    @classmethod
    def get_login(cls, config: DependsConfig):
        if not config.auth0.use:
            raise HTTPException(
                409,
                detail="Login is not available in pytest mode.",
            )

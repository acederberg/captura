# =========================================================================== #
import base64
import hashlib
import json
import secrets
from datetime import datetime
from typing import Annotated, Any, Dict

import httpx
from fastapi import Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import String, func, select
from sqlalchemy.orm import Mapped, mapped_column

# --------------------------------------------------------------------------- #
from captura import fields
from captura.auth import Token, TokenPermissionTier, try_decode
from captura.config import Config
from captura.controllers.base import Data, ResolvedUser
from captura.controllers.create import Create
from captura.controllers.read import Read
from captura.depends import DependsAuth, DependsConfig, DependsSessionMaker
from captura.models import Base, MappedColumnUUID, User
from captura.schemas import UserCreateSchema, mwargs
from captura.views.base import BaseView, OpenApiResponseCommon, OpenApiTags
from captura.views.users import UserView


def check_auth0_data(auth0_data: Dict[str, Any]):
    bad = set(v for v in AUTH0_KEYS if v not in auth0_data)
    if len(bad):
        detail = f"Missing expected fields `{bad}`."
        raise HTTPException(422, detail=detail)


def exclude_for(use_auth0: bool = True):
    mode = "auth0" if use_auth0 else "pytest"

    def wrapper(config: DependsConfig):
        if config.auth0.use is use_auth0:
            raise HTTPException(
                409,
                detail=f"Not available in `{mode}` mode.",
            )

    return wrapper


AUTH0_KEY_TOKEN_ACCESS = "access_token"
AUTH0_KEY_TOKEN_ID = "id_token"
AUTH0_KEYS = {AUTH0_KEY_TOKEN_ID, AUTH0_KEY_TOKEN_ACCESS}
DEMO_KEY_UUID = "demo_uuid"
DEMO_KEY_EXISTS_USER = "demo_exists_user"
DEMO_KEY_EXISTS = "demo_exists"


def form_body(cls):
    cls.__signature__ = cls.__signature__.replace(
        parameters=[
            arg.replace(default=Form(...))
            for arg in cls.__signature__.parameters.values()
        ]
    )
    return cls


def token_session(request: Request, auth: DependsAuth) -> Token:
    if (token := request.session.get(AUTH0_KEY_TOKEN_ACCESS)) is None:
        raise HTTPException(401, detail="Token required.")

    return Token.decode(auth, token, header=False)


DependsTokenSession = Annotated[Token, Depends(token_session)]


class AuthViewPytest(BaseView):
    """This is where routes to handle login and getting tokens will be."""

    view_routes = dict(
        post_register=dict(
            url="/register",
            name="",
            dependencies=[Depends(exclude_for(use_auth0=True))],
        ),
        post_token=dict(
            url="/token",
            name="Mint Test Token",
            dependencies=[Depends(exclude_for(use_auth0=True))],
        ),
        get_token=dict(
            url="/token",
            name="Verify Token",
        ),
    )
    view_router_args = dict(
        tags=[OpenApiTags.auth0],
        responses=OpenApiResponseCommon,
    )

    @classmethod
    def post_register(
        cls,
        sessionmaker: DependsSessionMaker,
        auth: DependsAuth,
        email: str,
        name: str,
        description: str,
        url_image: str | None = None,
        url: str | None = None,
    ) -> str:
        """Create user, return token."""

        try:
            registration_data = mwargs(
                UserCreateSchema,
                name=name,
                description=description,
                url_image=url_image,
                url=url,
                email=email,
            )
        except ValidationError as err:
            raise HTTPException(422, detail=err.json())

        with sessionmaker() as session:
            q = select(User.uuid).where(User.email == email)
            email_exists = session.scalar(q) is not None
            if email_exists:
                raise HTTPException(400, detail="Account with email already exists.")

            create = Create[UserCreateSchema](
                session,
                token=None,
                method="POST",
                api_origin="POST /register",
            )
            create.create_data = registration_data
            data: Data[ResolvedUser]
            data = mwargs(
                Data[ResolvedUser],
                token_user=None,
                data=ResolvedUser.empty(),
            )
            data_final = create.user(data)
            (user,) = data_final.data.users
            user.subject = hashlib.sha256(user.uuid.encode()).hexdigest()
            data_final.commit(create.session)

        token_final = mwargs(
            Token,
            sub=data_final.data.users[0].uuid,
            tier=TokenPermissionTier.paid,
        )
        return token_final.encode(auth)

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

        decoded, err = try_decode(auth, data, header=False)
        if err is not None:
            raise err

        assert decoded is not None
        # decoded["uuid"] = "sub"
        return Token.model_validate(decoded)


# NOTE: This is starting to follow the extension pattern. I might refactor it
#       as such later. At the moment this table can be created by running
#       ``simulatus initialize``
class Demo(Base):
    __tablename__ = "demos"

    uuid: Mapped[MappedColumnUUID] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(fields.LENGTH_NAME), unique=True)
    timestamp: Mapped[int] = mapped_column(
        default=(_now := lambda: datetime.timestamp(datetime.now())),
    )


class AuthViewAuth0(BaseView):

    view_routes = {
        "get_login": {
            "url": "/login",
            "tags": [OpenApiTags.auth0],
            "name": "Login Via Auth0",
            "description": "Login using auth0 and recieve a JWT.",
        },
        "get_logout": {
            "url": "/logout",
            "tags": [OpenApiTags.auth0],
            "name": "Logout",
        },
        "get_authorize": {
            "url": "/authorize",
            "tags": [OpenApiTags.auth0],
            "name": "Login Callback",
            "description": "Get a JSON web token.",
        },
        "get_register": {
            "url": "/register",
            "tags": [OpenApiTags.auth0],
            "name": "Register",
            "description": "Register a new user.",
        },
        "post_register": {
            "url": "/register",
            "tags": [OpenApiTags.auth0],
            "name": "Register",
            "description": "Register a new user.",
        },
        "get_profile": {
            "url": "/profile",
            "tags": [OpenApiTags.auth0],
            "name": "Profile",
            "description": "Profile.",
        },
        "get_demo": {
            "url": "/demo",
            "tags": [OpenApiTags.auth0],
            "name": "Request a Demo",
            "description": "Request a demo.",
        },
        "post_demo": {
            "url": "/demo",
            "tags": [OpenApiTags.auth0],
            "name": "Handle Demo Request.",
            "description": "Handle a demo request.",
        },
    }

    view_router_args = dict(dependencies=[Depends(exclude_for(use_auth0=False))])

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
        params += f"&audience={config.auth0.api.audience[0]}"
        url_auth0 = f"https://{config.auth0.issuer}/authorize{params}"

        return RedirectResponse(url_auth0)

    @classmethod
    async def get_logout(cls, request: Request):
        request.session.clear()
        return RedirectResponse("/", 302)

    @classmethod
    async def get_authorize(
        cls,
        request: Request,
        config: DependsConfig,
        sessionmaker: DependsSessionMaker,
        auth: DependsAuth,
        code: str,
    ):
        """Exchange the code for a token.

        Redirects new users to registration and existing users to their
        profile.
        """

        response = httpx.post(
            f"https://{config.auth0.issuer}/oauth/token",
            data=dict(
                redirect_uri=f"{config.app.host_url}/authorize",
                code=code,
                grant_type="authorization_code",
                # audience=config.auth0.api.audience,
                client_id=config.auth0.app.client_id,
                client_secret=config.auth0.app.client_secret.get_secret_value(),
            ),
        )
        if response.status_code != 200:
            detail = "Failed to exchange code for token."
            raise HTTPException(500, detail=detail)

        # NOTE: Ensure that the auth0 response is as expected.
        try:
            auth0_data = response.json()
        except json.JSONDecodeError as err_json:
            detail = "Failed to decode Auth0 response."
            raise HTTPException(500, detail=detail) from err_json

        # NOTE: Check the browser cookie and decode the token to get the
        #       subject.
        check_auth0_data(auth0_data)
        decoded, err = try_decode(
            auth, auth0_data[AUTH0_KEY_TOKEN_ACCESS], header=False
        )
        if err is not None:
            raise err

        assert decoded is not None
        subject_256 = hashlib.sha256(decoded["sub"].encode()).hexdigest()

        # NOTE: See RFC 6648. Make believe header to pass info on since query
        #       parameters are insecure (because of logging, etc).
        #       See further https://stackoverflow.com/questions/3561381/custom-http-headers-naming-conventions
        request.session.update({key: auth0_data[key] for key in AUTH0_KEYS})

        with sessionmaker() as session:
            q = select(func.count(User.uuid)).where(User.subject == subject_256)
            n = session.scalar(q)

        url = "/profile" if n else "/register"
        return RedirectResponse(url, status_code=302)

    # ----------------------------------------------------------------------- #
    # Registration

    @classmethod
    def check_code(cls, config: Config, email: str, code: str) -> None:

        # NOTE: Code to expect should be the sum of the salt and the users
        #       email address.
        code_expect = cls.create_code(config, email)
        if code != code_expect:
            raise HTTPException(403, detail="Invalid code.")

    @classmethod
    def create_code(cls, config: Config, email: str):
        return hashlib.sha256(
            config.auth0.registration_code_salt + email.encode()
        ).hexdigest()

    @classmethod
    async def get_register(
        cls,
        config: DependsConfig,
        auth: DependsAuth,
        request: Request,
    ):
        """This should return a form containing user creation parameters.

        Submission of this form should send `POST /register` with this data
        and then redirect the user to `/profile`
        """

        check_auth0_data(request.session)
        # access_token_raw = request.session[AUTH0_KEY_TOKEN_ACCESS]
        if AUTH0_KEY_TOKEN_ACCESS not in request.session:
            raise HTTPException(403, "Session missing `access_token`.")

        id_token_raw = request.session[AUTH0_KEY_TOKEN_ID]

        if len(id_token_split := id_token_raw.split(".")) == 3:
            _deco = base64.b64decode(id_token_split[1] + "==")
            id_token_decoded = json.loads(_deco)
        else:
            id_token_decoded = "Failed to decode `id_token`."

        # NOTE: Populate defaults from the id token.
        return cls.view_templates.TemplateResponse(
            request,
            name="register.j2",
            context=dict(id_token=id_token_decoded),
        )

    @classmethod
    async def post_register(
        cls,
        request: Request,
        auth: DependsAuth,
        sessionmaker: DependsSessionMaker,
        config: DependsConfig,
        code: str = Form(),
        email: str = Form(),
        name: str = Form(),
        description: str = Form(),
        url_image: str | None = Form(None),
        url: str | None = Form(None),
    ):
        """Accepts form data. Creates user. Redirects to profile."""

        check_auth0_data(request.session)
        access_token = auth.decode(
            request.session[AUTH0_KEY_TOKEN_ACCESS], header=False
        )
        subject = access_token["sub"]
        subject_256 = hashlib.sha256(subject.encode()).hexdigest()

        cls.check_code(config, email, code)
        try:
            registration_data = UserCreateSchema(
                content={},
                name=name,
                description=description,
                url_image=url_image,
                url=url,
                email=email,
            )
        except ValidationError as err:
            raise HTTPException(422, detail=err.json())

        with sessionmaker() as session:
            q = select(User.uuid).where(User.email == email)
            email_exists = session.scalar(q) is not None
            if email_exists:
                raise HTTPException(400, detail="Account with email already exists.")

            create = Create[UserCreateSchema](
                session,
                token=None,
                method="POST",
                api_origin="POST /register",
            )
            create.create_data = registration_data
            data: Data[ResolvedUser]
            data = mwargs(
                Data[ResolvedUser],
                token_user=None,
                data=ResolvedUser.empty(),
            )
            data_final = create.user(data)
            (user,) = data_final.data.users
            user.subject = subject_256
            data_final.commit(create.session)

        return RedirectResponse("/profile", 302)

    # ----------------------------------------------------------------------- #
    @classmethod
    async def get_demo(cls, request: Request):
        """Request a demo."""

        # NOTE: Maybe wrap in context instead?
        logged_in = request.session.get(AUTH0_KEY_TOKEN_ACCESS) is not None
        uuid = request.session.get(DEMO_KEY_UUID)
        exists = request.session.get(DEMO_KEY_EXISTS)
        exists_user = request.session.get(DEMO_KEY_EXISTS_USER)

        # NOTE: Says waiting for demo if already requested otherwises gets
        #       email and posts.
        return cls.view_templates.TemplateResponse(
            request,
            name="demo.j2",
            context=dict(
                uuid=uuid,
                logged_in=logged_in,
                exists=exists,
                exists_user=exists_user,
            ),
        )

    @classmethod
    async def post_demo(
        cls,
        request: Request,
        sessionmaker: DependsSessionMaker,
        email: Annotated[str, Form()],
    ) -> RedirectResponse:
        """Process demo data."""

        with sessionmaker() as session:
            # NOTE: Check if there is already a user with this email.
            user = session.scalar(select(User).where(User.email == email))
            if user is not None:
                request.session[DEMO_KEY_EXISTS_USER] = True
                return RedirectResponse(
                    "/demo",
                    status_code=302,
                )

            # NOTE: Check if demo exists.
            demo = session.scalar(select(Demo).where(Demo.email == email))
            exists = demo is not None
            if demo is None:
                demo = Demo(email=email)
                session.add(demo)
                session.commit()
                session.refresh(demo)

        request.session[DEMO_KEY_UUID] = demo.uuid
        request.session[DEMO_KEY_EXISTS] = exists
        request.session[DEMO_KEY_EXISTS_USER] = False

        return RedirectResponse(
            "/demo",
            status_code=302,
        )

    # NOTE: Save demo request somewhere.

    # ----------------------------------------------------------------------- #

    @classmethod
    async def get_profile(
        cls,
        request: Request,
        sessionmaker: DependsSessionMaker,
        token: DependsTokenSession,
    ):

        with sessionmaker() as session:
            read = Read(session, token, method="GET")
            user = token.validate_db(session)
            user_data = UserView.get_user(user.uuid, read)

        return cls.view_templates.TemplateResponse(
            request,
            name="profile.j2",
            context=dict(
                data=user_data,
                access_token=request.session[AUTH0_KEY_TOKEN_ACCESS],
            ),
        )

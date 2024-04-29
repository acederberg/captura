# =========================================================================== #
from typing import Annotated, Any, AsyncGenerator, Dict, Iterable, List, Self, Set

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI
from pydantic import BaseModel
from sqlalchemy import delete, select, text, true
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker as _sessionmaker

# --------------------------------------------------------------------------- #
from app import depends, util
from app.auth import Auth
from app.config import AppConfig
from app.models import Base, User
from app.schemas import mwargs
from app.views import AppView
from dummy import DummyHandler, DummyProvider, DummyProviderYAML
from tests.config import PytestClientConfig, PytestConfig

logger = util.get_logger(__name__)

# =========================================================================== #
# Test configuration and configuration fixture


# NOTE: Session scoping works like fastapi dependency caching, so these will
#       only ever be called once in a test session.
@pytest.fixture(scope="session")
def config() -> PytestConfig:
    logger.debug("Loading application configuration.")
    app = AppConfig.model_validate(
        {
            "logging_configuration_path": util.Path.base("logging.test.yaml"),
        }
    )
    if (config := mwargs(PytestConfig, app=app)).auth0.use:
        raise AssertionError(
            "Refusing to perform tests with `config.auth0.use=True`. "
            "Please set this setting to `False` to use the test token "
            "provider (see `app.config` and `app.auth::Auth.forPyTest`)."
        )

    return config


@pytest.fixture(scope="session")
def client_config() -> PytestClientConfig:
    logger.debug("Loading client configuration.")
    # raw: Dict[str, Any] = dict(
    #     hosts=dict(
    #         docker=dict(host="http://localhost:8080", remote=True),
    #         app=dict(host="http://localhost:8080", remote=False),
    #     ),
    #     profiles=dict(me=dict(token=None, uuid_user="000-000-000")),
    #     use=dict(host="app", profile="me"),
    # )
    return PytestClientConfig.model_validate({})


class PytestContext(BaseModel):
    reloaded: bool = False
    config: PytestConfig
    config_client: PytestClientConfig


@pytest.fixture(scope="session")
def context(
    config: PytestConfig,
    client_config: PytestClientConfig,
) -> PytestContext:
    logger.debug("Creating client context.")
    return PytestContext(config=config, config_client=client_config)


# --------------------------------------------------------------------------- #
# Application fixtures.


@pytest_asyncio.fixture(scope="session")
async def app(
    client_config: PytestClientConfig, config: PytestConfig
) -> FastAPI | None:
    if (host := client_config.host) is None or not host.remote:
        logger.info("Using httpx client with app instance.")

        # NOTE: Ensure that the pytest config is used. This step cannot be per-
        #       formed for remote hosts.
        app: FastAPI
        app = AppView.view_router  # type: ignore

        def config_callback():
            return config

        app.dependency_overrides[depends.config] = config_callback
        print("========================================")
        print(config.model_config.get("yaml_files"))
        return app
    else:
        logger.warning("Using remote host for testing. Not recommended in CI!")


@pytest.fixture(scope="session")
def auth(config: PytestConfig) -> Auth:
    return Auth.forPyTest(config)


# =========================================================================== #
# Database fixtures


@pytest.fixture(scope="session")
def engine(config: PytestConfig) -> Engine:
    logger.debug("Creating engine from application configuration.")
    return config.engine()


@pytest.fixture(scope="session")
def sessionmaker(engine: Engine) -> _sessionmaker[Session]:
    logger.debug("Creating sessionmaker from application configuration.")
    return _sessionmaker(engine)


@pytest.fixture(scope="function")
def session(sessionmaker):
    logger.debug("Session opened.")
    with sessionmaker() as session:
        yield session
    logger.debug("Session closed.")


# TODO: Try out module scoping.
@pytest.fixture(scope="module")
def dummy_handler(
    request, sessionmaker: _sessionmaker, config: PytestConfig, auth: Auth
):
    user_uuids: List[str] = list()
    handler = DummyHandler(
        sessionmaker,
        config,
        user_uuids,
        auth=auth,
    )

    logger.info("Cleaning an restoring database.")
    handler.create_report(f"Before disposal (`module={request.node.name}`).")
    handler.dispose()
    handler.create_report(f"After disposal (`module={request.node.name}`).")
    handler.restore()
    handler.create_report(f"After restoration (`module={request.node.name}`).")
    return handler


@pytest.fixture
def dummy(request, dummy_handler: DummyHandler):
    logger.info("Providing random dummy.")
    with dummy_handler.sessionmaker() as session:
        dummy = DummyProvider(
            dummy_handler.config,
            session,
            use_existing=dummy_handler.user_uuids,
            auth=dummy_handler.auth,
            client_config_cls=PytestClientConfig,
        )
        dummy.info_mark_used(request.node.name)
        session.add(dummy.user)
        session.commit()
        session.expire(dummy.user)

        yield dummy


@pytest.fixture
def dummy_new(request, dummy_handler: DummyHandler):
    logger.info("Providing new dummy.")
    with dummy_handler.sessionmaker() as session:
        dummy = DummyProvider(
            dummy_handler.config,
            session,
            auth=dummy_handler.auth,
            use_existing=None,
            client_config_cls=PytestClientConfig,
        )
        dummy.info_mark_used(request.node.name)
        session.add(dummy.user)
        session.commit()
        session.expire(dummy.user)

        yield dummy


@pytest.fixture
def dummy_disposable(request, dummy_handler: DummyHandler):
    logger.info("Providing disposable dummy.")
    with dummy_handler.sessionmaker() as session:
        dummy = DummyProvider(
            dummy_handler.config,
            session,
            auth=dummy_handler.auth,
            use_existing=dummy_handler.user_uuids,
            client_config_cls=PytestClientConfig,
        )
        dummy.info_mark_used(request.node.name).info_mark_tainted()
        session.add(dummy.user)
        session.commit()
        session.expire(dummy.user)

        yield dummy


@pytest.fixture(scope="function")
def yaml_dummy(request, dummy_handler: DummyHandler):
    logger.debug("Providing dummy for user uuid `000-000-000`.")
    with dummy_handler.sessionmaker() as session:
        user = session.get(User, 2)
        assert user is not None

        dd = DummyProviderYAML(
            dummy_handler.config,
            session,
            auth=dummy_handler.auth,
            user=user,
            client_config_cls=PytestClientConfig,
        )
        dd.merge(session)
        dd.session.refresh(dd.user)

        yield dd


# --------------------------------------------------------------------------- #
# Loading fixtures


@pytest.fixture(scope="session", autouse=True)
def setup_logging(config: PytestConfig) -> None:
    util.setup_logging(config.app.logging_configuration_path)
    return


@pytest.fixture(scope="session")
def setup_cleanup(engine: Engine, config: PytestConfig):
    logger.info("Setting up.")
    logger.debug("Verifying tables.")
    metadata = Base.metadata
    exists: bool
    with engine.begin() as connection:
        result = list(connection.execute(text("SHOW TABLES;")).scalars())
        exists = len(result) > 0

    if config.tests.recreate_tables and not exists:
        logger.debug("Recreating tables.")
        metadata.drop_all(engine)
        metadata.create_all(engine)
    elif not exists:
        logger.debug("Creating tables.")
        metadata.create_all(engine)
    else:
        logger.debug("Doing nothing to tables.")

    yield


@pytest.fixture(scope="session", autouse=True)
def load_tables(
    setup_cleanup, config: PytestConfig, auth: Auth, sessionmaker: _sessionmaker
):
    with sessionmaker() as session:
        logger.info("Loading tables with dummy data from `YAML`.")
        DummyProviderYAML.merge(session)
        logger.info("Generating dummy data.")

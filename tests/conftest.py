# =========================================================================== #
import json
from os import path
from random import choice
from typing import Any, AsyncGenerator, Dict, Generator, List, Set

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from pydantic import BaseModel, TypeAdapter
from sqlalchemy import func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker as _sessionmaker

# --------------------------------------------------------------------------- #
from app import util
from app.auth import Auth
from app.config import AppConfig, Config
from app.models import Base, User
from app.views import AppView
from client.config import Config as ClientConfig
from tests.config import PytestClientConfig, PytestConfig
from tests.test_models import ModelTestMeta

from .dummy import DummyProvider, DummyProviderYAML

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
    return PytestConfig(app=app)  # type: ignore


@pytest.fixture(scope="session")
def client_config() -> PytestClientConfig:
    logger.debug("Loading client configuration.")
    raw: Dict[str, Any] = dict(
        hosts=dict(
            docker=dict(host="http://localhost:8080", remote=True),
            app=dict(host="http://localhost:8080", remote=False),
        ),
        profiles=dict(me=dict(token=None, uuid_user="000-000-000")),
        use=dict(host="docker", profile="me"),
    )
    return PytestClientConfig(**raw)


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


# =========================================================================== #
# Database fixtures


@pytest.fixture(scope="session")
def engine(config: PytestConfig) -> Engine:
    logger.debug("Creating engine from application configuration.")
    return config.engine(echo=config.tests.emit_sql)


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
def load_tables(setup_cleanup, auth: Auth, sessionmaker: _sessionmaker):
    with sessionmaker() as session:
        logger.info("Loading tables with dummy data from `YAML`.")
        DummyProviderYAML.merge(session)
        uuids_existing = list(session.scalars(select(User.uuid)))
        n_users = len(uuids_existing)
        assert n_users is not None
        assert isinstance(n_users, int)

        # NOTE: This line is important!
        DummyProvider.dummy_user_uuids = uuids_existing

        logger.info("Loading tables with generated dummy data.")
        if (n_generate := 100 - n_users) > 0:
            while n_generate > 0:
                DummyProvider(auth, session)
                print(n_generate)
                n_generate -= 1

    return


# --------------------------------------------------------------------------- #
# Application fixtures.


@pytest_asyncio.fixture(scope="session")
async def app(client_config: ClientConfig) -> FastAPI | None:
    if (host := client_config.host) is None or not host.remote:
        return AppView.view_router  # type: ignore
    else:
        logger.warning("Using remote host for testing. Not recommended in CI!")


@pytest_asyncio.fixture(scope="session")
async def async_client(app: FastAPI | None) -> AsyncGenerator[httpx.AsyncClient, Any]:
    async with httpx.AsyncClient(app=app) as client:
        yield client


@pytest.fixture(scope="session")
def auth(config: Config) -> Auth:
    return Auth.forPyTest(config)


# =========================================================================== #


@pytest.fixture
def dummy(auth: Auth, session: Session) -> DummyProvider:
    logger.debug("Providing random dummy.")
    return DummyProvider(auth, session)


@pytest.fixture(scope="function")
def default(auth: Auth, session: Session) -> DummyProviderYAML:
    logger.debug("Providing dummy for user uuid `000-000-000`.")
    user = session.get(User, 2)
    assert user is not None
    dd = DummyProviderYAML(auth, session, user)
    dd.merge(session)
    dd.refresh()

    return dd

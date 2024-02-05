from typing import Annotated, Any, AnyStr, AsyncGenerator, Dict

import httpx
import pytest
import pytest_asyncio
from app import util
from app.auth import Auth
from app.config import Config
from app.models import Base
from app.views import AppView
from client.config import Config as ClientConfig
from client.config import ProfileConfig
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker as _sessionmaker
from yaml_settings_pydantic import YamlFileConfigDict, YamlSettingsConfigDict

from tests.test_models import ModelTestMeta

logger = util.get_logger(__name__)

# =========================================================================== #
# Test configuration and configuration fixture


class PytestSubConfig(BaseModel):
    """Configuration specific to pytest.

    :attr recreate_tables: Recreate tables or not in the ``engine`` fixture. If
        the tables do not exist, they will be created.
    """

    emit_sql: bool = False
    recreate_tables: bool = True


class PytestConfig(Config):
    """Configuration with additional pytest section.

    This should not be used in app.

    :attr tests: Test specific configuration.
    """

    model_config = YamlSettingsConfigDict(
        yaml_files=util.PATH_CONFIG_TEST_APP,
        env_prefix=util.ENV_PREFIX,
        env_nested_delimiter="__",
    )

    tests: PytestSubConfig


# NOTE: Session scoping works like fastapi dependency caching, so these will
#       only ever be called once in a test session.
@pytest.fixture(scope="session")
def config() -> PytestConfig:
    logger.debug(
        "`config` fixture called. Loading `%s`.",
        util.PATH_CONFIG_TEST_APP,
    )
    return PytestConfig()  # type: ignore


class PyTestClientProfileConfig(ProfileConfig):
    token: Annotated[str | None, Field()]  # type: ignore


class PytestClientConfig(ClientConfig):
    model_config = YamlSettingsConfigDict(
        yaml_files={
            util.PATH_CONFIG_TEST_CLIENT: YamlFileConfigDict(
                required=False,
                subpath=None,
            )
        }
    )

    profiles: Annotated[Dict[str, PyTestClientProfileConfig], Field()] = None  # type: ignore


@pytest.fixture(scope="session")
def client_config() -> PytestClientConfig:
    logger.debug(
        "`client_config` fixture called. Loading from `%s`.",
        util.PATH_CONFIG_TEST_CLIENT,
    )
    raw: Dict[str, Any] = dict(
        hosts=dict(
            docker=dict(host="http://localhost:8080", remote=True),
            app=dict(host="http://localhost:8080", remote=False),
        ),
        profiles=dict(me=dict(token=None, uuid_user="000-000-000")),
        use=dict(host="docker", profile="me"),
    )
    return PytestClientConfig(**raw)


# =========================================================================== #
# Database fixtures


@pytest.fixture(scope="session")
def engine(config: PytestConfig) -> Engine:
    logger.debug("`engine` fixture called.")
    return config.engine(echo=config.tests.emit_sql)


@pytest.fixture(scope="session")
def sessionmaker(engine: Engine) -> _sessionmaker[Session]:
    logger.debug("`sessionmaker` fixture called.")
    return _sessionmaker(engine)


# --------------------------------------------------------------------------- #
# Loading fixtures


@pytest.fixture(scope="session")
def load_tables(sessionmaker: _sessionmaker[Session], setup_cleanup):
    logger.info("Reloading tables (fixture `load_tables`).")
    with sessionmaker() as session:
        backwards = list(Base.metadata.sorted_tables)
        backwards.reverse()
        for table in backwards:
            logger.debug("Cleaning `%s`.", table.name)
            cls = ModelTestMeta.__children__.get(table.name)
            cls.clean(session)

        for table in Base.metadata.sorted_tables:
            cls = ModelTestMeta.__children__.get(table.name)
            if cls is None:
                logger.debug("No dummies for `%s`.", table.name)
                continue
            cls.load(session)


@pytest.fixture(scope="session")
def setup_cleanup(engine: Engine, config: PytestConfig):
    logger.debug("`setup_cleanup` fixture called.")
    metadata = Base.metadata
    exists: bool
    with engine.begin() as connection:
        result = list(connection.execute(text("SHOW TABLES;")).scalars())
        exists = len(result) > 0

    if config.tests.recreate_tables and exists:
        logger.debug("Recreating tables.")
        metadata.drop_all(engine)
        metadata.create_all(engine)
    elif not exists:
        logger.debug("Creating tables.")
        metadata.create_all(engine)

    yield


# --------------------------------------------------------------------------- #
# Application fixtures.


@pytest_asyncio.fixture
async def async_client(
    client_config: ClientConfig,
) -> AsyncGenerator[httpx.AsyncClient, Any]:
    client: httpx.AsyncClient

    app = None
    if (host := client_config.host) is None or host.remote:
        app = AppView.view_router
    else:
        logger.warning("Using remote host for testing. Not recommended in CI!")

    async with httpx.AsyncClient(
        app=app,
        base_url=client_config.host.host,
    ) as client:
        yield client


@pytest.fixture(scope="session")
def auth(config: Config) -> Auth:
    return Auth.forPyTest(config)

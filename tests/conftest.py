import pytest
from app import util
from app.config import PREFIX, Config
from app.models import Base
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker as _sessionmaker
from yaml_settings_pydantic import YamlFileConfigDict, YamlSettingsConfigDict

PATH_CONFIG_PYTEST = util.Path.base("config.test.yaml")
logger = util.get_logger(__name__)


class PytestSubConfig(BaseModel):
    """Configuration specific to pytest.

    :attr recreate_tables: Recreate tables or not in the ``engine`` fixture. If
        the tables do not exist, they will be created.
    """

    recreate_tables: bool = False


class PytestConfig(Config):
    """Configuration with additional pytest section.

    This should not be used in app.

    :attr tests: Test specific configuration.
    """

    model_config = YamlSettingsConfigDict(
        yaml_files=PATH_CONFIG_PYTEST,
        env_prefix=PREFIX,
        env_nested_delimiter="__",
    )

    tests: PytestSubConfig


print(PytestConfig())


# NOTE: Session scoping works like fastapi dependency caching, so these will
#       only ever be called once in a test session.
@pytest.fixture(scope="session")
def config() -> PytestConfig:
    logger.debug("`config` fixture called. Loading `%s`.", PATH_CONFIG_PYTEST)
    return PytestConfig()  # type: ignore


@pytest.fixture(scope="session")
def engine(config: Config) -> Engine:
    logger.debug("`engine` fixture called.")
    return config.engine()


@pytest.fixture(scope="session")
def sessionmaker(engine: Engine) -> _sessionmaker[Session]:
    logger.debug("`sessionmaker` fixture called.")
    return _sessionmaker(engine)


@pytest.fixture(scope="session", autouse=True)
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

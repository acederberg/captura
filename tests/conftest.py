import pytest
from app.config import Config
from app.models import Base
from sqlalchemy.engine import Engine


@pytest.fixture(scope="session")
def config() -> Config:
    return Config()


@pytest.fixture(scope="session")
def engine(config) -> Engine:
    return config.engine()


@pytest.fixture(scope="session", autouse=True)
def setup_cleanup(config):
    metadata = Base.metadata
    engine = config.engine()
    metadata.create_all(engine)

    yield

    metadata.drop_all(engine)

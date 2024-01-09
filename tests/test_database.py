from sqlalchemy.engine import Engine
from sqlalchemy.sql import text


def test_fixture_works(engine: Engine, setup_cleanup):
    with engine.begin() as connection:
        result = list(connection.execute(text("SHOW TABLES;")).scalars())
        assert len(result) == 7

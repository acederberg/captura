from sqlalchemy.engine import Engine
from sqlalchemy.sql import text


def test_fixture_works(engine: Engine):
    with engine.begin() as connection:
        result = list(connection.execute(text("SHOW TABLES;")).scalars())
        assert len(result) == 7

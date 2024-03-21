from app.models import User
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.sql import text


def test_fixture_works(engine: Engine, sessionmaker, load_tables):
    """Make sure that the dummy providers are working."""

    with engine.begin() as connection:
        result = list(connection.execute(text("SHOW TABLES;")).scalars())
        assert len(result) == 7

    with sessionmaker() as session:
        n_users = session.execute(select(func.count(User.uuid))).scalar()
        assert n_users is not None
        assert n_users >= 7

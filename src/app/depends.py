"""This module contains all of the depends that will be needed in variou
endpoints.

The code behind most of the functions here should be in other modules, for
instance `auth` or `config`, except in the case that it is dependency used to
trap and transform api parameters. No exports (things in ``__all__``) should
be wrapped in ``Depends``.
"""
from functools import cache
from typing import Annotated, Callable

from fastapi import Depends
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import Config

# NOTE: `cache` is used instead of using the `use_cache` keyword argument of
#       `Depends` because it will result in identical object ids. For instance
#       this means that `session_maker` will always return the same session
#       maker.


@cache
def config() -> Config:
    return Config()


@cache
def engine(config: Annotated[Config, Depends(config)]) -> Engine:
    return config.engine()


@cache
def session_maker(engine: Annotated[Engine, Depends(engine)]) -> sessionmaker[Session]:
    return sessionmaker(engine)

# =========================================================================== #
from typing import Annotated, Any, Dict, List, Tuple

from pydantic import Field

# --------------------------------------------------------------------------- #
from app.config import BaseHashable
from app.schemas import mwargs


def test_hash():
    # NOTE: Unhashables are ignored.
    class Example(BaseHashable):
        hashable_fields_exclude = {"ex"}

        ex: str
        foo: Tuple[str, ...]

    assert Example.hashable_fields_exclude == {"ex"}

    # NOTE: Completely different, should not match.
    example_a = Example(foo=("bar", "spam", "eggs"), ex="a")
    example_b = Example(foo=("whatever",), ex="b")
    assert hash(example_a) != hash(example_b)

    # NOTE: Match on nonexcluded fields, so hash should match.
    example_b = Example(foo=("bar", "spam", "eggs"), ex="b")
    assert hash(example_a) == hash(example_b)

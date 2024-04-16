# =========================================================================== #
import secrets
from datetime import datetime
from random import choice, randint
from typing import Any, Callable, Dict, Generic, List, Protocol, Type, TypeVar

from faker import Faker
from faker.providers import internet
from sqlalchemy import Column, inspect

# --------------------------------------------------------------------------- #
from app import __version__
from app.fields import (
    LENGTH_CONTENT,
    LENGTH_DESCRIPTION,
    LENGTH_MESSAGE,
    LENGTH_NAME,
    LENGTH_URL,
)
from app.models import (
    Collection,
    Document,
    Event,
    Format,
    Grant,
    KindEvent,
    KindObject,
    Level,
    PendingFrom,
    User,
)

fkit = Faker()
fkit.add_provider(internet)
_item_kind_event: List[KindEvent] = list(KindEvent)
_item_kind_obj: List[KindObject] = list(KindObject)
_item_format: List[Format] = list(Format)
_item_pending_from: List[PendingFrom] = list(PendingFrom)
_item_level: List[Level] = list(Level)
_now = int(datetime.timestamp(datetime.utcnow()))
_Mk: Dict[str, Callable[[], Any]] = dict(
    kind=lambda: choice(_item_kind_event),
    api_version=lambda: __version__,
    timestamp=lambda: randint(0, _now),
    uuid=lambda: secrets.token_urlsafe(8),
    name=lambda: fkit.text(LENGTH_NAME),
    description=lambda: fkit.text(LENGTH_DESCRIPTION),
    detail=lambda: fkit.text(LENGTH_DESCRIPTION),
    url=lambda: fkit.url()[:LENGTH_URL],
    url_image=lambda: fkit.url()[:LENGTH_URL],
    level=lambda: Level(randint(1, 3)),
    pending_from=lambda: choice(_item_pending_from),
    kind_obj=lambda: choice(_item_kind_obj),
    kind_event=lambda: choice(_item_kind_event),
    format=lambda: choice(_item_format),
    content=lambda: bytes(fkit.text(LENGTH_CONTENT), "utf-8"),
    message=lambda: fkit.text(LENGTH_MESSAGE),
    admin=(mk_bool := lambda: bool(randint(0, 1))),
    deleted=mk_bool,
    public=mk_bool,
    pending=mk_bool,
    api_origin=lambda: "tests/dummy.py",
    info=lambda: dict(dummy=dict(used_by=list(), tainted=False), tags=[]),
)


def get_mk(column: Column):
    if column.name.startswith("uuid"):
        return  # _Mk["uuid"]
    elif column.name.startswith("id"):
        return
    elif column.name.startswith("_prototype"):
        return

    match column:
        case Column(primary_key=True):
            return
        case _:
            return _Mk[column.name]  # type: ignore


T_ResolvableContra = TypeVar(
    "T_ResolvableContra",
    Collection,
    User,
    Document,
    Grant,
    Event,
    covariant=True,
)


class MkDummyProvider(Protocol, Generic[T_ResolvableContra]):
    def __call__(self, **kwargs) -> T_ResolvableContra:
        ...


def create_mk_dummy(
    T_model: Type[T_ResolvableContra],
) -> MkDummyProvider[T_ResolvableContra]:
    cols = {
        col.name: mk
        for col in inspect(T_model).columns
        if (mk := get_mk(col)) is not None
    }

    def wrapper(**kwargs) -> T_ResolvableContra:
        base_kwargs = {key: mk() for key, mk in cols.items()}
        base_kwargs.update(kwargs)
        return T_model(**base_kwargs)

    return wrapper


class Mk:
    user = staticmethod(create_mk_dummy(User))
    collection = staticmethod(create_mk_dummy(Collection))
    document = staticmethod(create_mk_dummy(Document))
    grant = staticmethod(create_mk_dummy(Grant))
    event = staticmethod(create_mk_dummy(Event))

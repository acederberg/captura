# =========================================================================== #
import enum
import secrets
import uuid
from datetime import datetime
from typing import Annotated, Any, Callable, Dict, Set, Type, TypeAlias

from pydantic import BeforeValidator, Field

LENGTH_NAME: int = 96
LENGTH_TITLE: int = 128
LENGTH_DESCRIPTION: int = 256
LENGTH_URL: int = 256


class Level(enum.Enum):
    # NOTE: Must be consisten with sql, indexes start at 1
    view = 1
    modify = 2
    own = 3

    @classmethod
    def resolve(cls, v: "ResolvableLevel") -> "Level":
        match v:
            case LevelStr() as lvlstr:
                return Level[lvlstr.name]
            case Level() as self:
                return self
            case bad:
                raise ValueError(f"Cannot resolve level for `{bad}`.")


class LevelStr(str, enum.Enum):
    view = "view"
    modify = "modify"
    own = "own"


ResolvableLevel: TypeAlias = str | Level | LevelStr


class LevelHTTP(enum.Enum):
    DELETE = Level.own
    PUT = Level.modify
    POST = Level.modify
    PATCH = Level.modify
    GET = Level.view


class KindEvent(str, enum.Enum):
    create = "create"
    upsert = "upsert"
    update = "update"
    delete = "delete"
    grant = "grant"
    restore = "restore"


class PendingFrom(enum.Enum):
    created = 3
    granter = 2
    grantee = 1


class PendingFromStr(str, enum.Enum):
    created = "created"
    granter = "granter"
    grantee = "grantee"


# NOTE: This maps table names to their corresponding API names. It is important
#       to note that this uses singular names and not plural names.
class KindObject(str, enum.Enum):
    bulk = "bulk"
    user = "users"
    document = "documents"
    collection = "collections"
    edit = "edits"
    event = "events"
    assignment = "assignments"
    grant = "grants"


class Plural(str, enum.Enum):
    user = "users"
    document = "documents"
    collection = "collections"
    edit = "edits"
    event = "events"
    assignment = "assignments"
    grant = "grants"


class Singular(str, enum.Enum):
    events = "event"
    users = "user"
    documents = "document"
    collections = "collection"
    edits = "edit"
    assignments = "assignment"
    grants = "grant"


class KindRecurse(str, enum.Enum):
    depth_first = "depth-first"
    bredth_first = "bredth_first"


class ChildrenUser(str, enum.Enum):
    users = "users"
    collections = "collections"
    documents = "documents"
    edits = "edits"


class ChildrenCollection(str, enum.Enum):
    documents = "documents"
    edits = "edits"


class ChildrenDocument(str, enum.Enum):
    edits = "edits"


class ChildrenAssignment(str, enum.Enum):
    documents = "documents"
    collections = "collections"


class ChildrenGrant(str, enum.Enum):
    documents = "documents"
    users = "users"


FieldUUID = Annotated[
    str,
    _FieldUUID := Field(
        length=32,
        # min_length=32,
        # max_length=32,
        description="Universally unique identifier for an object.",
        examples=[uuid.uuid4()],
    ),
]
FieldUUIDOptional = Annotated[str | None, _FieldUUID]

FieldUnixTimestamp = Annotated[
    None | int,
    Field(
        description="Unix timestamp.",
        examples=[int(datetime.now().timestamp())],
    ),
]
FieldUnixTimestampOptional: TypeAlias = Annotated[
    datetime | None,
    Field(
        default=None,
        description="Optional unix timestamp.",
    ),
]

FieldName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=LENGTH_NAME,
        description="Object name.",
        examples=["New Mexican Recipes", "Trails", "Software"],
    ),
]
FieldDescription = Annotated[
    str,
    Field(
        min_length=1,
        max_length=LENGTH_DESCRIPTION,
        description="Object description",
        examples=["This is a document/user/collection description."],
    ),
]
FieldUrl = Annotated[
    str | None,
    Field(
        min_length=8,
        max_length=LENGTH_URL,
        description="User url.",
        examples=["https://github.com/acederberg"],
    ),
]

EXAMPLE_CONTENT = (
    "orem ipsum dolor sit amet, consectetur adipiscing elit, sed do "
    "eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut "
    "enim ad minim veniam, quis nostrud exercitation ullamco laboris "
    "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor "
    "in reprehenderit in voluptate velit esse cillum dolore eu fugiat "
    "nulla pariatur. Excepteur sint occaecat cupidatat non proident, "
    "sunt in culpa qui officia deserunt mollit anim id est laborum."
)

FieldUUIDS = Annotated[
    Set[str] | None,
    Field(
        default=None,
        description="UUIDs to filter with.",
        examples=[set(secrets.token_urlsafe() for _ in range(25))],
    ),
]
FieldID = Annotated[int, Field(description="Primary key(s) for tables.")]

FieldPending = Annotated[
    bool,
    Field(description="Grant awaiting approval (or not)."),
]
# FieldPendingFrom = Annotated[
#     PendingFrom,
#     Field(description="Grant initiator."),
# ]
FieldDeleted = Annotated[
    bool,
    Field(description="Object pending deletion or not."),
]
FieldDetail = Annotated[
    str | None,
    Field(default=None, description="Event detail."),
]
FieldLimitOptional: TypeAlias = Annotated[int | None, Field(default=None)]
FieldNameLike = Annotated[
    str | None,
    Field(
        description="Search objects for a name like this.",
        examples=["foobar", "billy mays"],
        default=None,
    ),
]
FieldDescriptionLike = Annotated[
    str | None,
    Field(
        description="Search objects for a description like this.",
        examples=["dolor sit amit,"],
        default=None,
    ),
]


def int_enum_from_name(
    EnumSubclass: Type[enum.Enum], callback: Callable[[Any], Any] | None = None
) -> Callable[[Any], Any]:
    def wrapper(v: Any) -> Any:
        match v:
            case EnumSubclass():  # type: ignore
                return v
            case str() as v_str:
                return EnumSubclass[v_str]
            case int() as v_int:
                return EnumSubclass(v_int)

        if callback is not None:
            v = callback(v)
        return v

    return wrapper


def int_enum_from_name_callback(v) -> None | Level:
    if isinstance(v, LevelStr):
        return FieldLevel(v.name)
    return v


FieldLevel = Annotated[
    Level,
    Field(description="Access level for grant."),
    BeforeValidator(int_enum_from_name(Level, int_enum_from_name_callback)),
]

FieldPendingFrom = Annotated[
    PendingFrom,
    Field(description="Grant pending origin."),
    BeforeValidator(int_enum_from_name(PendingFrom)),
]

FieldKindEvent = Annotated[
    KindEvent | None,
    Field(
        default=None,
        description="Event opperation tag.",
    ),
]

FieldKindObject = Annotated[
    KindObject | None,
    Field(
        default=None,
        description="Target object type. Often this is the name of corresponding table.",
        examples=[
            KindObject.user,
            KindObject.collection,
            KindObject.document,
        ],
    ),
]
FieldEmail = Annotated[
    str,
    Field(description="User email.", examples=["example1234@some.io"]),
]


FieldContent: TypeAlias = Annotated[
    Dict[str, Any] | None,
    Field(description="Document content.", default=None),
]


__all__ = (
    "ChildrenAssignment",
    "ChildrenCollection",
    "ChildrenDocument",
    "ChildrenGrant",
    "ChildrenUser",
    "KindEvent",
    "KindObject",
    "KindRecurse",
    "Level",
    "LevelHTTP",
    "LevelStr",
    "PendingFrom",
    "Plural",
    "Singular",
)

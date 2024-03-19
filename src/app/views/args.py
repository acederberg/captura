from typing import Annotated, Literal, Optional, Set, TypeAlias

# from app.fields import FieldLevel, KindEvent, KindObject, KindRecurse, LevelStr
from app import fields
from fastapi import Path, Query

PathUUIDUser: TypeAlias = Annotated[str, Path(description="User uuids.")]
PathUUIDCollection: TypeAlias = Annotated[str, Path(description="Collection uuids.")]
PathUUIDDocument: TypeAlias = Annotated[str, Path(description="Document uuids.")]
PathUUIDEvent: TypeAlias = Annotated[str, Path(description="Event uuids.")]
PathUUIDObj: TypeAlias = Annotated[str, Path(description="Object uuids.")]
PathKindObj: TypeAlias = Annotated[fields.FieldKindEvent, Path(description="Object kind.")]

# --------------------------------------------------------------------------- #

# NOTE: Due to how `q_conds_` works (with empty `set()` versus `None`) the
#       empty set cannot be allowed. When nothing is passed it ought to be
#       `None`.
QueryUUIDCollection: TypeAlias = Annotated[
    Set[str],
    Query(
        min_length=1,
        description="Collection uuids to filter by.",
    ),
]
QueryUUIDCollectionOptional: TypeAlias = Annotated[
    Optional[Set[str]],
    Query(
        min_length=1,
        description="Optional collection uuids to filter by.",
    ),
]

# --------------------------------------------------------------------------- #

# QueryUUIDOwner: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDDocument: TypeAlias = Annotated[
    Set[str],
    Query(
        min_length=1,
        description="Document uuids to filter by.",
    ),
]
QueryUUIDDocumentOptional: TypeAlias = Annotated[
    Optional[Set[str]],
    Query(
        min_length=1,
        description="Optional document uuids to filter by.",
    ),
]

# --------------------------------------------------------------------------- #

QueryUUIDUser: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDUserOptional: TypeAlias = Annotated[
    Optional[Set[str]],
    Query(
        min_length=1,
        description="Optional user uuids to filter by.",
    ),
]

# --------------------------------------------------------------------------- #

QueryUUIDEditOptional: TypeAlias = Annotated[
    Optional[Set[str]],
    Query(min_length=1, description="Optional edit uuids to filter by."),
]

# --------------------------------------------------------------------------- #

QueryForce: TypeAlias = Annotated[
    bool, Query(description="When true, objects cannot be restored.")
]
QueryLevel: TypeAlias = Annotated[fields.LevelStr, Query()]
QueryLevelOptional: TypeAlias = Annotated[fields.LevelStr | None, Query()]

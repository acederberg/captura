from fastapi import Path, Query
from typing import Optional, TypeAlias, Annotated, Set, Literal
from app.models import KindObject, KindEvent, KindRecurse

QueryUUIDCollection: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDOwner: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDDocument: TypeAlias = Annotated[Set[str], Query(min_length=1)]
QueryUUIDUser: TypeAlias = Annotated[Set[str], Query(min_length=1)]

PathUUIDUser: TypeAlias = Annotated[str, Path()]
PathUUIDCollection: TypeAlias = Annotated[str, Path()]
PathUUIDDocument: TypeAlias = Annotated[str, Path()]
PathUUIDEvent: TypeAlias = Annotated[str, Path()]

# NOTE: Due to how `q_conds_` works (with empty `set()` versus `None`) the
#       empty set cannot be allowed. When nothing is passed it ought to be
#       `None`.
QueryUUIDCollectionOptional: TypeAlias = Annotated[
    Optional[Set[str]],
    Query(min_length=1),
]
QueryUUIDDocumentOptional: TypeAlias = Annotated[
    Optional[Set[str]],
    Query(min_length=1),
]
QueryUUIDUserOptional: TypeAlias = Annotated[
    Optional[Set[str]],
    Query(min_length=1),
]
QueryUUIDEditOptional: TypeAlias = Annotated[
    Optional[Set[str]],
    Query(min_length=1),
]

QueryLevel: TypeAlias = Annotated[Literal["view", "modify", "own"], Query()]
QueryRestore: TypeAlias = Annotated[bool, Query()]
QueryTree: TypeAlias = Annotated[bool, Query()]
QueryRoots: TypeAlias = Annotated[bool, Query()]
QueryKindEvent: TypeAlias = Annotated[Optional[KindEvent], Query()]
QueryKindObject: TypeAlias = Annotated[Optional[KindObject], Query()]
QueryUUIDEventObject: TypeAlias = Annotated[Optional[str], Query()]
QueryFlat: TypeAlias = Annotated[bool, Query()]
QueryKindRecurse: TypeAlias = Annotated[Optional[KindRecurse], Query()]
QueryForce: TypeAlias = Annotated[bool, Query()]

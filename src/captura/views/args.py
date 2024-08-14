# =========================================================================== #
from typing import Annotated, Optional, Set, TypeAlias

from fastapi import Depends, HTTPException, Path, Query

# --------------------------------------------------------------------------- #
# from captura.fields import FieldLevel, KindEvent, KindObject, KindRecurse, LevelStr
from captura import fields

PathUUIDUser: TypeAlias = Annotated[str, Path(description="User uuids.")]
PathUUIDCollection: TypeAlias = Annotated[str, Path(description="Collection uuid.")]
PathUUIDDocument: TypeAlias = Annotated[str, Path(description="Document uuid.")]
PathUUIDEvent: TypeAlias = Annotated[str, Path(description="Event uuid.")]
PathUUIDObj: TypeAlias = Annotated[str, Path(description="Arbitrary object uuid.")]
PathKindObj: TypeAlias = Annotated[
    fields.FieldKindEvent, Path(description="Object kind.")
]

# --------------------------------------------------------------------------- #

# NOTE: Due to how `q_conds_` works (with empty `set()` versus `None`) the
#       empty set cannot be allowed. When nothing is passed it ought to be
#       `None`.
QueryUUIDCollectionOptional: TypeAlias = Annotated[
    Optional[Set[str]],
    Query(
        min_length=1,
        description="Optional collection uuids to filter by.",
    ),
]


def query_uuid_collection(
    uuid_collection: QueryUUIDCollectionOptional = None,
) -> Set[str]:
    # NOTE: See `uuid_user`.
    if uuid_collection is None:
        raise HTTPException(
            422, detail="Missing required `uuid_collection` query parameter."
        )
    return uuid_collection


QueryUUIDCollection: TypeAlias = Annotated[
    Optional[Set[str]], Depends(query_uuid_collection)
]

# --------------------------------------------------------------------------- #

QueryUUIDDocumentOptional: TypeAlias = Annotated[
    Set[str] | None,
    Query(
        min_length=1,
        description="Uuids to filter by.",
    ),
]


def query_uuid_document(uuid_document: QueryUUIDDocumentOptional = None) -> Set[str]:
    # NOTE: See `uuid_user`.
    if uuid_document is None:
        raise HTTPException(
            422, detail="Missing required `uuid_document` query parameter."
        )
    return uuid_document


QueryUUIDDocument: TypeAlias = Annotated[
    Optional[Set[str]], Depends(query_uuid_document)
]

# --------------------------------------------------------------------------- #

QueryUUIDUserOptional: TypeAlias = Annotated[
    Optional[Set[str]],
    Query(
        min_length=1,
        description="Optional user uuids to filter by.",
    ),
]


def query_uuid_user(uuid_user: QueryUUIDUserOptional = None) -> Set[str]:
    # NOTE: This is done because urls with no parameters will result in a 500.
    #       The message recieved is:

    #       .. code:: stdout
    #
    #           fastapi.exceptions.RequestValidationError: [
    #               {'type': 'set_type', 'loc': ('query', 'uuid_user'),
    #                'msg': 'Input should be a valid set',
    #                'input': PydanticUndefined,
    #                'url': 'https://errors.pydantic.dev/2.6/v/set_type'}
    #           ]
    if uuid_user is None:
        raise HTTPException(422, "Missing required `uuid_user` query parameter.")
    return uuid_user


QueryUUIDUser: TypeAlias = Annotated[Optional[Set[str]], Depends(query_uuid_user)]

# --------------------------------------------------------------------------- #

QueryForce: TypeAlias = Annotated[
    bool, Query(description="When true, objects cannot be restored.")
]
QueryLevel: TypeAlias = Annotated[fields.LevelStr, Query()]
QueryLevelOptional: TypeAlias = Annotated[fields.LevelStr | None, Query()]
QueryPendingFromOptional: TypeAlias = Annotated[fields.PendingFromStr | None, Query()]

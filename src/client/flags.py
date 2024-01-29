import pathlib
from app.models import KindEvent, KindObject
import yaml
import enum
import typer
from app.models import (
    ChildrenUser,
    ChildrenCollection,
    ChildrenDocument,
    LevelStr,
    KindRecurse,
)
from typing import TypeVar, TypeAlias, Annotated, List, Optional


class Verbage(str, enum.Enum):
    read = "read"
    read_document = "read_document"
    read_user = "read_user"

    search = "search"
    restore = "restore"
    update = "update"
    delete = "delete"
    create = "create"

    apply = "apply"
    destroy = "destroy"


class Output(str, enum.Enum):
    json = "json"
    yaml = "yaml"
    table = "table"


# --------------------------------------------------------------------------- #
# UUID Flags and Arguments
# NOTE: Annotations should eventually include help.

FlagOutput: TypeAlias = Annotated[Output, typer.Option("--output", "-o")]
FlagUUIDChildrenOptional: TypeAlias = Annotated[
    List[str], typer.Option("--uuid-child", "--uuid-children")
]


# User

ArgUUIDUser: TypeAlias = Annotated[str, typer.Argument(help="User uuid.")]
FlagUUIDUserOptional: TypeAlias = Annotated[
    Optional[str],
    typer.Option(
        "--uuid-user",
        help="Transfer ownship of a collection to this UUID.",
    ),
]
FlagUUIDUsers: TypeAlias = Annotated[
    List[str], typer.Option("--uuid-user", help="A required list of user UUIDs.")
]
FlagUUIDUsersOptional: TypeAlias = Annotated[
    Optional[List[str]],
    typer.Option("--uuid-user", help="An optional list of user UUIDs."),
]


# Documents

FlagUUIDDocuments: TypeAlias = Annotated[List[str], typer.Option("--uuid-document")]
FlagUUIDDocumentsOptional: TypeAlias = Annotated[
    Optional[List[str]], typer.Option("--uuid-document")
]
ArgUUIDDocument: TypeAlias = Annotated[str, typer.Argument()]


# Collections

FlagUUIDCollections: TypeAlias = Annotated[List[str], typer.Option("--uuid-collection")]
FlagUUIDCollectionsOptional: TypeAlias = Annotated[
    List[str], typer.Option("--uuid-collection")
]
ArgUUIDCollection: TypeAlias = Annotated[str, typer.Argument()]

# Events

FlagUUIDEvent = Annotated[str, typer.Option("--uuid-event")]
FlagUUIDEventOptional = Annotated[Optional[str], typer.Option("--uuid-event")]

# --------------------------------------------------------------------------- #
# Field flags


FlagColumns: TypeAlias = Annotated[List[str], typer.Option("--column")]
FlagLevel: TypeAlias = Annotated[LevelStr, typer.Option("--level")]
FlagName = Annotated[Optional[str], typer.Option("--name")]
FlagDescription = Annotated[Optional[str], typer.Option("--description")]
FlagUrl = Annotated[Optional[str], typer.Option("--url")]
FlagUrlImage = Annotated[Optional[str], typer.Option("--url-image")]
FlagPublic = Annotated[bool, typer.Option("--public/--private")]
FlagPublicOptional = Annotated[Optional[bool], typer.Option("--public/--private")]
FlagForce = Annotated[bool, typer.Option("--force/--no-force")]
FlagKindRecurse: TypeAlias = Annotated[KindRecurse, typer.Option("--recurse-strategy")]
FlagNameLike: TypeAlias = Annotated[Optional[str], typer.Option("--name-like")]
FlagDescriptionLike: TypeAlias = Annotated[
    Optional[str], typer.Option("--description-like")
]
FlagLimit: TypeAlias = Annotated[int, typer.Option("--limit")]


# --------------------------------------------------------------------------- #
# Children flags

FlagChildrenUser: TypeAlias = Annotated[
    Optional[ChildrenUser], typer.Option("--child", "--children")
]
FlagChildrenCollection: TypeAlias = Annotated[
    ChildrenCollection, typer.Option("--child", "--children")
]
FlagChildrenDocument: TypeAlias = Annotated[
    ChildrenDocument, typer.Option("--child", "--children")
]

# --------------------------------------------------------------------------- #
# Events flags

ArgUUIDEvent: TypeAlias = Annotated[str, typer.Argument()]
FlagFlatten: TypeAlias = Annotated[
    bool,
    typer.Option(
        "--flatten/--heads",
        help="Return only heads (entries with no parents).",
    ),
]
FlagKind: TypeAlias = Annotated[
    Optional[KindEvent],
    typer.Option("--kind", "-k", help="Matches against the `kind` field."),
]
FlagKindObject: TypeAlias = Annotated[
    Optional[KindObject],
    typer.Option(
        "--object",
        "-j",
        help="Object kind, matches again the `kind_obj` field.",
    ),
]
FlagUUIDEventObject: TypeAlias = Annotated[
    Optional[str],
    typer.Option(
        "--uuid-object",
        "--uuid",
        help="Target object UUID.",
    ),
]

# --------------------------------------------------------------------------- #
# Configuration Flags.

FlagHost: TypeAlias = Annotated[
    Optional[str],
    typer.Option(
        "--host",
        help="Host from configuration to use.",
    ),
]
FlagProfile: TypeAlias = Annotated[
    Optional[str],
    typer.Option(
        "--profile",
        "-p",
        help="Profile from configuration to use.",
    ),
]

# --------------------------------------------------------------------------- #
# Loader flags.

ArgFilePath: TypeAlias = Annotated[
    pathlib.Path,
    typer.Argument(help="Path to the apply file."),
]

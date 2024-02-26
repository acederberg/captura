import enum
import pathlib
from typing import Annotated, List, Optional, TypeAlias, TypeVar

import typer
from app.models import (
    ChildrenCollection,
    ChildrenDocument,
    ChildrenUser,
    KindEvent,
    KindObject,
    KindRecurse,
    LevelStr,
)


class Verbage(str, enum.Enum):
    read = "read"
    read_document = "read_document"
    read_user = "read_user"

    search = "search"
    restore = "restore"
    update = "update"
    delete = "delete"
    create = "create"
    activate = "activate"

    # apply = "apply"
    # destroy = "destroy"


class Output(str, enum.Enum):
    json = "json"
    yaml = "yaml"
    table = "table"


# --------------------------------------------------------------------------- #
# UUID Flags and Arguments
# NOTE: Annotations should eventually include help.

FlagOutput: TypeAlias = Annotated[Output, typer.Option("--output", "-o")]
FlagUUIDs: TypeAlias = Annotated[Optional[List[str]], typer.Option("--uuid")]


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
    List[str],
    typer.Option(
        "--uuid-user",
        help="A required list of user UUIDs.",
    ),
]
FlagUUIDUsersOptional: TypeAlias = Annotated[
    Optional[List[str]],
    typer.Option(
        "--uuid-user",
        help="An optional list of user UUIDs.",
    ),
]

FlagInvitationCode: TypeAlias = Annotated[
    str,
    typer.Option(
        "--invitation-code",
        help="The invitation code to approve/verify a demo user with.",
    ),
]
FlagInvitationEmail: TypeAlias = Annotated[
    str,
    typer.Option(
        "--invitation-email",
        help="The email corresponding the invitation code.",
    ),
]
FlagInvitationCodesOptional: TypeAlias = Annotated[
    Optional[List[str]],
    typer.Option(
        "--invitation-code",
        help="Invitation codes to search by.",
    ),
]
FlagInvitationEmailsOptional: TypeAlias = Annotated[
    Optional[List[str]],
    typer.Option(
        "--invitation-email",
        help="Invitation emails to search by.",
    ),
]


# --------------------------------------------------------------------------- #
# Documents

FlagUUIDDocuments: TypeAlias = Annotated[List[str], typer.Option("--uuid-document",
                                                                 help="Document uuids."),]
FlagUUIDDocumentsOptional: TypeAlias = Annotated[
    Optional[List[str]], typer.Option("--uuid-document", help="Optional document uuids.",),
]
ArgUUIDDocument: TypeAlias = Annotated[str, typer.Argument()]


# --------------------------------------------------------------------------- #
# Collections

FlagUUIDCollections: TypeAlias = Annotated[List[str], typer.Option("--uuid-collection")]
FlagUUIDCollectionsOptional: TypeAlias = Annotated[
    List[str], typer.Option("--uuid-collection")
]
ArgUUIDCollection: TypeAlias = Annotated[str, typer.Argument()]


# --------------------------------------------------------------------------- #
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

# --------------------------------------------------------------------------- #
# Search flags


FlagNameLike: TypeAlias = Annotated[Optional[str], typer.Option("--name-like")]
FlagDescriptionLike: TypeAlias = Annotated[
    Optional[str], typer.Option("--description-like")
]
FlagIncludePublic: TypeAlias = Annotated[int, typer.Option("--include-public")]
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

# --------------------------------------------------------------------------- #
# Token flags

FlagTokenOptional: TypeAlias = Annotated[
    Optional[str], typer.Option(help="Specifies the token to use for any request.")
]
ArgTokenPayload: TypeAlias = Annotated[
    str, typer.Option(help="Data for token payload.")
]

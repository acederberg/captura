from typing import Any, ClassVar, Dict, Generic, List, TypeVar

from fastapi import HTTPException
from pydantic import BaseModel

from app import fields

# --------------------------------------------------------------------------- #
# Error Message Schemas.
# 
# These are important for clients that might want to use these and for testing.
# It also makes it such that all errors come from the same origin.


class ErrBase(BaseModel):
    msg: Any
    # _msg_bad_method = "Method not allowed."

    @classmethod
    def httpexception(cls, msg_name: str, status: int, *, dump_kwargs: Dict[str, Any] = dict(), **kwargs,) -> HTTPException:
        if (msg := getattr(cls, msg_name, None)) is None:
            raise ValueError("No message named 'msg_name'.")

        kwargs.update(msg=msg)
        self = cls(**kwargs)
        return HTTPException(status, detail=self.model_dump(mode="json", **dump_kwargs))


class ErrObjMinSchema(ErrBase):
    _msg_deleted_grant: ClassVar[str] = "Grant has been deleted."
    _msg_deleted: ClassVar[str] = "Object has been deleted."
    _msg_dne: ClassVar[str] = "Object does not exist."

    uuid_obj: fields.FieldUUID
    kind_obj: fields.FieldKindEvent | fields.FieldKindObject


class ErrAccessUser(ErrBase):
    _msg_private: ClassVar[str] = "Cannot access private user."
    _msg_modify: ClassVar[str] = "Cannot modify user."

    uuid_user: fields.FieldUUID
    uuid_user_token: fields.FieldUUID


class ErrAccessCollection(ErrBase):
    _msg_private: ClassVar[str] = "Cannot access private collection."
    _msg_modify: ClassVar[str] = "Cannot modify collection."
    _msg_homeless: ClassVar[str] = "Collection has no owner."

    uuid_user_token: fields.FieldUUID
    uuid_collection: fields.FieldUUID


# --------------------------------------------------------------------------- #


class ErrAccessEvent(ErrBase):
    _msg_not_owner: ClassVar[str] = "Cannot access event."

    uuid_event: fields.FieldUUID


class ErrEventGeneral(ErrBase):
    _msg_no_root: ClassVar[str] = "Could not find parent event. Inconcievable!"

    uuid_event: fields.FieldUUID


class ErrEventKind(ErrEventGeneral):
    _msg_kind_event: ClassVar[str] = "Unexpected value for `kind_obj`."
    _msg_uuid_obj: ClassVar[str] = "Unexpected value for `uuid_obj`."

    kind: fields.FieldKindObject | fields.FieldKindEvent
    kind_expected: fields.FieldKindObject | fields.FieldKindEvent
    uuid_event: fields.FieldUUID


class ErrEventUndone(ErrEventGeneral):
    _msg_undone: ClassVar[str] = "Cannot undo undone event."

    uuid_event: fields.FieldUUID
    uuid_event_undo: fields.FieldUUID


# --------------------------------------------------------------------------- #


class ErrAccessDocumentGrantBase(ErrBase):
    _msg_dne: ClassVar[str] = "Grant does not exist."
    _msg_inconcievable: ClassVar[str] = "Inconcievable!"

    uuid_document: fields.FieldUUID
    uuid_user: fields.FieldUUID
    level_grant_required: fields.FieldLevel


class ErrAccessDocumentGrantInsufficient(ErrAccessDocumentGrantBase):
    _msg_insufficient: ClassVar[str] = "Grant insufficient."

    uuid_grant: fields.FieldUUID
    level_grant: fields.FieldLevel


class ErrAccessDocumentPending(ErrAccessDocumentGrantInsufficient):
    _msg_grant: ClassVar[str] = "Grant is pending."
    _msg_grant_created_pending: ClassVar[str] = "Grant is pending with `pending_from=created`."

    pending_from: fields.FieldPendingFrom


class ErrAccessDocumentCannotRejectOwner(ErrBase):
    uuid_user_revoker: fields.FieldUUID
    uuid_document: fields.FieldUUID
    uuid_user_revokees: fields.FieldUUIDS


# --------------------------------------------------------------------------- #


T_ErrDetail = TypeVar("T_ErrDetail", bound=BaseModel | str)


class ErrDetail(BaseModel, Generic[T_ErrDetail]):
    detail: T_ErrDetail


AnyErrDetailAccessDocumentGrant = (ErrDetail[ErrAccessDocumentGrantBase] |
    ErrDetail[ErrAccessDocumentGrantInsufficient] |
    ErrDetail[ErrAccessDocumentPending])




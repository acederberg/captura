import secrets
from functools import cached_property
from http import HTTPMethod
from typing import Any, Dict, Generic, Set, Tuple, Type, TypeVar, overload

from app import __version__
from app.auth import Token
from app.models import (Assignment, Collection, Document, Event, KindEvent,
                        KindObject, ResolvableMultiple, ResolvableSingular,
                        ResolvableSourceAssignment, ResolvableTargetAssignment,
                        Tables, User)
from app.schemas import (AssignmentSchema, CollectionCreateSchema,
                         CollectionSchema, CollectionUpdateSchema,
                         DocumentCreateSchema, DocumentUpdateSchema,
                         EditCreateSchema, EventSchema, GrantCreateSchema,
                         PostUserSchema, UserCreateSchema, UserUpdateSchema)
from app.views.access import Access, H, WithAccess, with_access
from app.views.base import (Data, DataResolvedGrant,
                            ResolvedAssignmentCollection,
                            ResolvedAssignmentDocument, ResolvedCollection,
                            ResolvedDocument, ResolvedEdit,
                            ResolvedGrantDocument, ResolvedGrantUser,
                            ResolvedUser)
from app.views.delete import (AssocData, DataResolvedAssignment, Delete,
                              WithDelete)
from fastapi import HTTPException
from sqlalchemy import Delete as sqaDelete
from sqlalchemy import Update, literal_column, select
from sqlalchemy.orm import Session

T_Upsert = TypeVar(
    "T_Upsert",
    CollectionUpdateSchema,
    CollectionCreateSchema,
    DocumentUpdateSchema,
    DocumentCreateSchema,
    UserUpdateSchema,
    UserCreateSchema,
    GrantCreateSchema,
    EditCreateSchema,
)


class Upsert(WithDelete, Generic[T_Upsert]):

    _upsert_data: T_Upsert | None

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
        *,
        detail: str,
        api_origin: str,
        force: bool = True,
        access: Access| None = None,
        delete: Delete | None = None,
        upsert_data: T_Upsert = None,
    ):
        super().__init__(
            session,
            token,
            method,
            detail=detail,
            api_origin=api_origin,
            force=force,
            access=access,
            delete=delete
        )
        self._upsert_data = upsert_data

    @property
    def upsert_data(self) -> T_Upsert:
        if (upsert_data := self._upsert_data) is None:
            raise AttributeError("`upsert_data` is not yet set.")
        return upsert_data

    @upsert_data.setter
    def upsert_data(self, v: T_Upsert):
        self._upsert_data = v


    # ----------------------------------------------------------------------- #
    # Helpers

    @property
    def event_common(self) -> Dict[str, Any]:
        kind = KindEvent.create if self.method == H.POST else KindEvent.update
        return dict(**super().event_common, kind=kind)

    # @overload
    # def assoc(self, data: Data[ResolvedAssignmentCollection]) -> Data[ResolvedAssignmentCollection]: ...  # type: ignore
    #
    # @overload
    # def assoc(self, data: Data[ResolvedAssignmentDocument]) -> Data[ResolvedAssignmentDocument]: ...  # type: ignore
    #
    # @overload
    # def assoc(self, data: Data[ResolvedGrantUser]) -> Data[ResolvedGrantUser]: ...
    #
    # @overload
    # def assoc(
    #     self, data: Data[ResolvedGrantDocument]
    # ) -> Data[ResolvedGrantDocument]: ...
    @overload
    def assoc(
        self,
        data: Data[ResolvedGrantUser],
    ) -> Tuple[
        Data[ResolvedGrantUser],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]: ...

    @overload
    def assoc(
        self,
        data: Data[ResolvedGrantDocument],
    ) -> Tuple[
        Data[ResolvedGrantDocument],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]: ...

    @overload
    def assoc(
        self,
        data: Data[ResolvedAssignmentDocument],
    ) -> Tuple[
        Data[ResolvedAssignmentDocument],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]: ...

    @overload
    def assoc(
        self,
        data: Data[ResolvedAssignmentCollection],
    ) -> Tuple[
        Data[ResolvedAssignmentCollection],
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]: ...


    def assoc(
        self, data: DataResolvedGrant | DataResolvedAssignment
    ) -> Tuple[
        DataResolvedGrant | DataResolvedAssignment,
        AssocData,
        Update[Assignment] | sqaDelete[Assignment],
        Type[Assignment],
    ]:
        """Symetrically handle forced creation.

        When :attr:`force` is ``True``, lingering assignments staged for
        deletion will be cleaned up by :attr:`delete`. Otherwise, if
        :param:`data` specified exising assignments, an error will be raised.

        :returns: The active target ids that do not yet have an assignment to
            their source. The requirement that they be active means that doing
            the same `POST` twice should be indempotent.
        """
        # Create the deletion statement (if it is needed), e
        session = self.session
        data, rm_assoc_data, rm_q, T_assoc = self.delete.assoc(data)

        uuid_target_create: Set[str]
        uuid_target_create = data.data.uuid_target.copy()  # type: ignore
        uuid_target_create -= rm_assoc_data.uuid_target_active
        match self.method:
            case H.POST if not self.force:
                if rm_assoc_data.uuid_assoc_deleted:
                    msg = "Some targets have existing assignments awaiting "
                    msg += "cleanup. Try this request again with `force=true` "
                    msg += "or make an equivalent `PUT` request."
                    raise HTTPException(
                        400,
                        detail=dict(
                            msg=msg,
                            kind_target=data.data.kind_target,
                            kind_source=data.data.kind_source,
                            kind_assoc=data.data.kind_assoc,
                            uuid_target=rm_assoc_data.uuid_target_deleted,
                            uuid_source=data.data.uuid_source,
                            uuid_assoc=rm_assoc_data.uuid_assoc_deleted,
                        ),
                    )
            # NOTE: Delete existing, add deleted to created.
            case H.POST | H.PUT:
                session.execute(rm_q)
                uuid_target_create |= rm_assoc_data.uuid_target_deleted
            case _:
                raise HTTPException(405)

        # NOTE: Create assocs.
        id_source_name = f"id_{data.data.kind_source}"
        id_target_name = f"id_{data.data.kind_target}"

        id_source_value = data.data.source.uuid  # type: ignore
        targets: Tuple = data.data.target  # Type: ignore
        assocs = tuple(
            T_assoc(
                **{
                    id_source_name: id_source_value,
                    id_target_name: target.id,
                    "uuid": secrets.token_urlsafe(8),
                    **self.upsert_data.model_dump(),
                }
            )
            for target in targets
            if target.uuid in uuid_target_create
        )
        session.add(assocs)

        # NOTE: Create event.
        target_attr_name = data.data.kind_target.name
        uuid_target_attr_name = f"uuid_{target_attr_name}"
        event_common = self.event_common
        event = Event(
            **event_common,
            uuid_obj=data.data.uuid_source,
            kind_obj=data.data.kind_source,
            children=[
                Event(
                    **event_common,
                    kind_obj=data.data.kind_target,
                    uuid_obj=getattr(assoc, uuid_target_attr_name),
                    children=[
                        Event(
                            **event_common,
                            kind_obj=data.data.kind_assoc,
                            uuid_obj=assoc.uuid,
                        )
                    ],
                )
                for assoc in assocs
            ],
        )
        session.add(event)
        if data.event is not None:
            data.event.children.insert(0, event)
        else:
            data.event = event
        session.commit()

        return data, rm_assoc_data, rm_q, T_assoc

    # ----------------------------------------------------------------------- #
    # Assocs

    def assignment_document(
        self,
        data: Data[ResolvedAssignmentDocument],
    ) -> Data[ResolvedAssignmentDocument]:
        data, *_ = self.assoc(data)
        return data

    def assignment_collection(
        self,
        data: Data[ResolvedAssignmentCollection],
    ) -> Data[ResolvedAssignmentCollection]:
        data, *_ = self.assoc(data)
        return data

    def grant_user(
        self,
        data: Data[ResolvedGrantUser],
    ) -> Data[ResolvedGrantUser]:
        data, *_ = self.assoc(data)
        return data

    def grant_document(
        self,
        data: Data[ResolvedGrantDocument],
    ) -> Data[ResolvedGrantDocument]:
        data, *_ = self.assoc(data)
        return data

    # ----------------------------------------------------------------------- #
    # Others

    def user(self, data: Data[ResolvedUser]) -> Data[ResolvedUser]: ...

    def collection(
        self,
        data: Data[ResolvedCollection],
    ) -> Data[ResolvedCollection]: ...

    # NOTE:
    def document(
        self,
        data: Data[ResolvedDocument],
    ) -> Data[ResolvedDocument]: ...
    def edit(
        self,
        data: Data[ResolvedEdit],
    ) -> Data[ResolvedEdit]: ...

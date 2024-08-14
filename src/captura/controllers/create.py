# =========================================================================== #
import secrets
from http import HTTPMethod
from typing import Any, Callable, Dict, Generic, Set, Tuple, TypeVar, overload

from fastapi import HTTPException
from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- #
from captura.auth import Token
from captura.controllers.access import Access, H, with_access
from captura.controllers.base import (
    Data,
    DataResolvedGrant,
    KindData,
    ResolvedAssignmentCollection,
    ResolvedAssignmentDocument,
    ResolvedCollection,
    ResolvedDocument,
    ResolvedEvent,
    ResolvedGrantDocument,
    ResolvedGrantUser,
    ResolvedUser,
)
from captura.controllers.delete import (
    AssocData,
    DataResolvedAssignment,
    Delete,
    WithDelete,
)
from captura.err import ErrAssocRequestMustForce
from captura.models import (
    Assignment,
    Collection,
    Document,
    Event,
    Grant,
    KindEvent,
    KindObject,
    Level,
    PendingFrom,
    User,
)
from captura.schemas import (
    CollectionCreateSchema,
    CollectionUpdateSchema,
    DocumentCreateSchema,
    DocumentUpdateSchema,
    GrantCreateSchema,
    UserCreateSchema,
    UserUpdateSchema,
    mwargs,
)

# Typehints for assoc callback.
# NOTE: Tried protocol, too much of a pain in the ass.


AssocCallbackGrant = Callable[
    [
        Data[ResolvedGrantDocument] | Data[ResolvedGrantUser],
        User | Document,
    ],
    Grant,
]
AssocCallbackAssignment = Callable[
    [
        Data[ResolvedAssignmentDocument] | Data[ResolvedAssignmentCollection],
        Collection | Document,
    ],
    Assignment,
]
AssocCallback = AssocCallbackGrant | AssocCallbackAssignment

# --------------------------------------------------------------------------- #


# T_with_empty_data_self = TypeVar(
#     "T_with_empty_data_self",
#     bound=WithDelete,
# )
#

# NOTE: Apply to methods like :func:`with_access`. In this case access is only
#       checked by verifying that the user has a valid token.
#       The goal is to create empty data and use that as the entry point
#       instead of a method of :class:`Access`
# def with_empty_data(
#     meth: Callable[[T_with_empty_data_self, Data[T_Data]], Data[T_Data]],
# ) -> Callable[[T_with_empty_data_self, Data[T_Data] | None], Data[T_Data]]:
#
#     def reject_nonempty(
#         self: T_with_empty_data_self, data: Data[T_Data] | None = None
#     ) -> Data[T_Data]:
#         data: Data[T_Data]
#         if data is None:
#             data = Data[T_Data].model_vali
#
#         data_empty = data
#
#         return meth(self, data)
#
#     reject_nonempty.__name__ = meth.__name__
#     reject_nonempty.__doc__ = meth.__doc__
#
#     return reject_nonempty


# --------------------------------------------------------------------------- #
# Generic upsert.

T_Create = TypeVar(
    "T_Create",
    CollectionCreateSchema,
    DocumentCreateSchema,
    UserCreateSchema,
    GrantCreateSchema,
)


class Create(WithDelete, Generic[T_Create]):
    # NOTE: `PUT` will only be supported on assignments and grants for now
    #       (force overwriting of existing). This is because `PATCH` will be
    #       used to accept grants by grant uuid.

    _create_data: T_Create | None

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
        *,
        api_origin: str,
        force: bool = False,
        access: Access | None = None,
        delete: Delete | None = None,
        create_data: T_Create | None = None,
    ):
        if method != H.POST and method != H.PUT:
            msg = f"Cannot accept method `{method}` (expected one of `PUT` or "
            raise ValueError(msg + "`PATCH`.")

        super().__init__(
            session,
            token,
            method,
            api_origin=api_origin,
            force=force,
            access=access,
            delete=delete,
        )
        self._create_data = create_data

    @property
    def create_data(self) -> T_Create:
        if (create_data := self._create_data) is None:
            raise AttributeError("`create_data` is not yet set.")
        return create_data

    @create_data.setter
    def create_data(self, v: T_Create):
        self._create_data = v

    # ----------------------------------------------------------------------- #
    # Helpers

    @property
    def event_common(self) -> Dict[str, Any]:
        kind = KindEvent.create if self.method == H.POST else KindEvent.update
        return dict(**super().event_common, kind=kind)

    # TODO: Make this work with generics.
    def assoc(
        self,
        data: DataResolvedGrant | DataResolvedAssignment,
        create_assoc: AssocCallback,
    ) -> Tuple[DataResolvedGrant | DataResolvedAssignment, AssocData]:
        """Symetrically handle forced creation.

        When :attr:`force` is ``True``, lingering assignments staged for
        deletion will be cleaned up by :attr:`delete`. Otherwise, if
        :param:`data` specified exising assignments, an error will be raised.

        :param assoc_args: Common arguments for creating the associations. This
            should be everything that is not specified by :param:`data` or
            :attr:`create_data`. For instance, grant should pass key value
            pairs for ``pending_from`` and ``uuid_parent``. This parameter
            should be used for internal values and not user inputs, which
            should be added to `create_data`.
        :returns: The active target ids that do not yet have an assignment to
            their source. The requirement that they be active means that doing
            the same `POST` twice should be indempotent.
        """

        # NOTE: By default, only create for those that hove no assocs.
        assoc_data, model_assoc = self.delete.split_assocs(data)
        uuid_target_create = assoc_data.uuid_target_none.copy()

        if self.method != HTTPMethod.POST:
            raise HTTPException(405)

        event_rm: Event | None = None
        if not self.force:
            if assoc_data.uuid_assoc_deleted:
                raise ErrAssocRequestMustForce.httpexception(
                    "_msg_force",
                    400,
                    kind_target=data.data.kind_target,
                    kind_source=data.data.kind_source,
                    kind_assoc=data.data.kind_assoc,
                    uuid_target=list(assoc_data.uuid_target_deleted),
                    uuid_source=data.data.uuid_source,
                    uuid_assoc=list(assoc_data.uuid_assoc_deleted),
                )
        else:
            q_del, uuid_assoc_rm = assoc_data.q_del(model_assoc, True, rm_active=False)
            q_assocs = model_assoc.q_uuid(uuid_assoc_rm)
            assocs_rm = tuple(self.session.scalars(q_assocs))

            self.session.execute(q_del)
            event_rm = self.delete.create_event_assoc(data, assocs_rm)
            uuid_target_create |= assoc_data.uuid_target_deleted

        targets = tuple(tt for tt in data.data.target if tt.uuid in uuid_target_create)
        assocs: Dict[str, Grant] | Dict[str, Assignment] = {
            target.uuid: create_assoc(data, target)  # type: ignore
            for target in targets
        }

        # WARNING! OVERWRITES!
        resolved_raw = {
            data.data._attr_name_source: data.data.source,
            data.data._attr_name_target: targets,
            data.data._attr_name_assoc: assocs,
        }
        if data.data.kind_assoc == KindObject.grant:
            resolved_raw["token_user_grants"] = getattr(data.data, "token_user_grants")

        data_final: DataResolvedGrant | DataResolvedAssignment = mwargs(
            Data[data.data.__class__],  # type: ignore
            data=data.data.__class__.model_validate(resolved_raw),
        )

        event_create = self.create_event_assoc(data_final, assocs)
        if event_rm is not None:
            event = Event(
                **self.event_common,
                uuid_obj=data_final.data.uuid_source,
                kind_obj=data_final.data.kind_source,
                children=[event_rm, event_create],
            )
            event.kind = KindEvent.upsert
        else:
            event = event_create

        data_final.event = event
        setattr(data_final.data, data_final.data._attr_name_assoc, assocs)

        # ------------------------------------------------------------------- #
        #
        # NOTE: This snippet was helpful in debugging, do not delete.
        # import json
        # from pydantic import TypeAdapter
        # from rich.table import Table
        # from captura.schemas import AssignmentSchema, GrantSchema
        #
        # table = Table(show_lines=False, show_header=False)
        # table.add_column()
        # table.add_column()
        # table.add_row("data.data.assoc", str(data.data.assoc))
        # table.add_row("self.force", str(self.force))
        # table.add_row("assoc_data", assoc_data.render())
        # self.session.add_all(assocs.values())
        # table.add_row(
        #     "assocs",
        #     str([[aa.uuid_collection, aa.uuid_document] for aa in assocs.values()]),
        # )
        # table.title = "From Create"
        #
        # ------------------------------------------------------------------- #

        return data_final, assoc_data

    def create_event_assoc(
        self,
        data: DataResolvedGrant | DataResolvedAssignment,
        grants: Dict[str, Grant] | Dict[str, Assignment],
    ) -> Event:
        return Event(
            **(event_common := self.event_common),
            uuid=secrets.token_urlsafe(8),
            uuid_obj=data.data.uuid_source,
            kind_obj=data.data.kind_source,
            children=[
                Event(
                    **event_common,
                    uuid=secrets.token_urlsafe(8),
                    kind_obj=data.data.kind_target,
                    uuid_obj=uuid_target,
                    children=[
                        Event(
                            **event_common,
                            uuid=secrets.token_urlsafe(8),
                            kind_obj=data.data.kind_assoc,
                            uuid_obj=grant.uuid,
                        )
                    ],
                )
                for uuid_target, grant in grants.items()
            ],
        )

    # ----------------------------------------------------------------------- #
    # Assocs
    # @overload
    # def create_assignment(
    #     self,
    #     data: Data[ResolvedAssignmentCollection],
    #     target: Document,
    # ) -> Assignment: ...
    #
    # @overload
    # def create_assignment(
    #     self,
    #     data: Data[ResolvedAssignmentDocument],
    #     target: Collection,
    # ) -> Assignment: ...

    def create_assignment(
        self,
        data: Data[ResolvedAssignmentDocument] | Data[ResolvedAssignmentCollection],
        target: Collection | Document,
    ) -> Assignment:
        id_source_name = f"id_{data.data.kind_source.name}"
        id_target_name = f"id_{data.data.kind_target.name}"
        id_source_value = data.data.source.id  # type: ignore

        kwargs = {
            "uuid": secrets.token_urlsafe(8),
            id_source_name: id_source_value,
            id_target_name: target.id,
        }
        return Assignment(
            **kwargs,
            **self.create_data.model_dump(),
        )

    def assignment_document(
        self,
        data: Data[ResolvedAssignmentDocument],
    ) -> Data[ResolvedAssignmentDocument]:
        data, *_ = self.assoc(data, self.create_assignment)  # type: ignore[assignment]
        assert data.event
        return data

    def assignment_collection(
        self,
        data: Data[ResolvedAssignmentCollection],
    ) -> Data[ResolvedAssignmentCollection]:
        data, *_ = self.assoc(data, self.create_assignment)  # type: ignore[assignment]
        return data

    # @overload
    # def create_grant(
    #     self,
    #     data: Data[ResolvedGrantDocument],
    #     target: User,
    # ) -> Grant: ...
    #
    # @overload
    # def create_grant(
    #     self,
    #     data: Data[ResolvedGrantUser],
    #     target: Document,
    # ) -> Grant: ...

    def create_grant(
        self,
        data: Data[ResolvedGrantDocument] | Data[ResolvedGrantUser],
        target: Document | User,
    ) -> Grant:
        # NOTE: Grants should be indexed by uuids of documents.
        grant_parent_uuid: str | None
        match data.data.kind_source:
            case KindObject.document:
                # NOTE: Permission of granter since they are inviting a user in
                #       this case. This means that the invitor (a user who
                #       already owns the document) will be the one responsible
                #       for the grants creation.
                parent_grants = data.data.token_user_grants.values()
                if not (n := len(parent_grants)):
                    detail = dict(
                        msg="No parent grant.",
                        uuid_target=target.uuid,
                        uuid_source=data.data.source.uuid,
                        kind_target=data.data.kind_target,
                        kind_source=data.data.kind_source,
                    )
                    raise HTTPException(403, detail=detail)
                elif n > 1:
                    raise HTTPException(500, detail="Granter has too many grants.")

                (parent_grant,) = parent_grants
                grant_parent_uuid = parent_grant.uuid
                pending_from = PendingFrom.grantee
            case KindObject.user:
                grant_parent_uuid = None
                # ^^^^^^^^^^^^^^^^^ Assigned later by granter who accepts the
                #                   request. Grant of the granter to remove
                #                   this from pending state will be created
                #                   later.
                pending_from = PendingFrom.granter
            case bad:
                raise ValueError(f"Invalid source `{bad}`.")

        id_source_name = f"id_{data.data.kind_source.name}"
        id_target_name = f"id_{data.data.kind_target.name}"
        id_source_value = data.data.source.id  # type: ignore

        kwargs = {
            "uuid": secrets.token_urlsafe(8),
            "uuid_parent": grant_parent_uuid,
            "pending_from": pending_from,
            "pending": True,
            id_source_name: id_source_value,
            id_target_name: target.id,
        }
        return Grant(**kwargs, **self.create_data.model_dump())

    def grant_user(
        self,
        data: Data[ResolvedGrantUser],
    ) -> Data[ResolvedGrantUser]:
        data, *_ = self.assoc(data, self.create_grant)  # type: ignore[assignment]
        return data

    def grant_document(
        self,
        data: Data[ResolvedGrantDocument],
    ) -> Data[ResolvedGrantDocument]:
        data, *_ = self.assoc(data, self.create_grant)  # type: ignore[assignment]
        return data

    a_assignment_document = with_access(Access.assignment_document)(assignment_document)
    a_assignment_collection = with_access(Access.assignment_collection)(
        assignment_collection
    )
    a_grant_document = with_access(Access.grant_document)(grant_document)
    a_grant_user = with_access(Access.grant_user)(grant_user)

    # ----------------------------------------------------------------------- #
    # Others
    #
    # NOTE: Nested creation will not be put here. That will be done later after
    #       an initial release.

    def user(
        self,
        data: Data[ResolvedUser],
    ) -> Data[ResolvedUser]:
        user = User(
            **self.create_data.model_dump(),
            uuid=(uuid_user := secrets.token_urlsafe(8)),
        )
        data_create = data.empty(KindData.user)
        data_create.data.users = (user,)
        data_create.event = Event(
            **self.event_common,
            uuid_user=uuid_user,
            kind_obj=KindObject.user,
            uuid_obj=uuid_user,
            detail="User created.",
        )
        return data_create

    # NOTE: Ideally consuming functions would just pass in an empty data and
    #       this would fill it out. Unfortunately mutations make things more
    #       complicated so the behaviour here is not as such.
    def collection(
        self,
        data: Data[ResolvedCollection],
    ) -> Data[ResolvedCollection]:
        collection = Collection(
            **self.create_data.model_dump(),
            user=data.token_user,
            uuid=(uuid_collection := secrets.token_urlsafe(8)),
        )
        data_create = data.empty(KindData.collection)
        data_create.data.collections = (collection,)
        data_create.event = Event(
            **self.event_common,
            kind_obj=KindObject.collection,
            uuid_obj=uuid_collection,
            detail="Collection created.",
        )

        return data_create

    def document(
        self,
        data: Data[ResolvedDocument],
    ) -> Data[ResolvedDocument]:
        uuid_document, uuid_grant = (secrets.token_urlsafe(8) for _ in range(2))
        user = data.token_user or self.token_user
        data.data.documents = (
            document := Document(
                **self.create_data.model_dump(),
            ),
        )

        data.data.token_user_grants = {
            user.uuid: (
                Grant(
                    id_user=user.id,
                    id_document=document.id,
                    level=Level.own,
                    pending=False,
                    pending_from=PendingFrom.created,
                    uuid=uuid_grant,
                    # id_user_granter=user.id,
                )
            )
        }
        data.event = Event(
            **self.event_common,
            kind_obj=KindObject.document,
            uuid_obj=uuid_document,
            detail="Document created.",
            children=[
                Event(
                    **self.event_common,
                    kind_obj=KindObject.user,
                    uuid_obj=user.uuid,
                    detail="Ownership granted by creation.",
                    children=[
                        Event(
                            **self.event_common,
                            kind_obj=KindObject.grant,
                            uuid_obj=uuid_grant,
                            detail="Ownership created for user.",
                        )
                    ],
                )
            ],
        )
        return data

    # e_document = with_empty_data(document)


# --------------------------------------------------------------------------- #
# Update.

T_Update = TypeVar(
    "T_Update",
    CollectionUpdateSchema,
    DocumentUpdateSchema,
    UserUpdateSchema,
    bool,  # approve or reject grant
)


class Update(WithDelete, Generic[T_Update]):
    _update_data: T_Update | None

    def __init__(
        self,
        session: Session,
        token: Token | Dict[str, Any] | None,
        method: HTTPMethod | str,
        *,
        api_origin: str,
        force: bool = False,
        access: Access | None = None,
        delete: Delete | None = None,
        update_data: T_Update | None = None,
    ):
        if method != H.PATCH:
            msg = f"Cannot accept method `{method}` (expected one of `PUT` or "
            raise ValueError(msg + "`PATCH`).")

        super().__init__(
            session,
            token,
            method,
            api_origin=api_origin,
            force=force,
            access=access,
            delete=delete,
        )
        self._update_data = update_data

    @property
    def update_data(self) -> T_Update:
        if (v := self._update_data) is None:
            raise ValueError("`update_data` has not been set.")
        return v

    @update_data.setter
    def update_data(self, v) -> None:
        if self._update_data is not None:
            raise ValueError("Cannot overwrite existing update data.")
        self._update_data = v

    @property
    def event_common(self) -> Dict[str, Any]:
        v = super().event_common
        v.update(kind=KindEvent.update)
        return v

    @overload
    def generic_update(
        self,
        data: Data[ResolvedUser],
        exclude: Set[str] = set(),
        commit: bool = True,
    ) -> Tuple[Data[ResolvedUser], UserUpdateSchema]: ...

    @overload
    def generic_update(
        self,
        data: Data[ResolvedCollection],
        exclude: Set[str] = set(),
        commit: bool = True,
    ) -> Tuple[Data[ResolvedCollection], CollectionUpdateSchema]: ...

    @overload
    def generic_update(
        self,
        data: Data[ResolvedDocument],
        exclude: Set[str] = set(),
        commit: bool = True,
    ) -> Tuple[Data[ResolvedDocument], DocumentUpdateSchema]: ...

    # NOTE: Document updates are not generic
    def generic_update(
        self,
        data: Data[ResolvedUser] | Data[ResolvedCollection] | Data[ResolvedDocument],
        exclude: Set[str] = set(),
        commit: bool = True,
    ) -> (
        Tuple[Data[ResolvedUser], UserUpdateSchema]
        | Tuple[Data[ResolvedCollection], CollectionUpdateSchema]
        | Tuple[Data[ResolvedDocument], DocumentUpdateSchema]
    ):
        session = self.session

        item: User | Collection | Document
        match data.data:
            case object(users=(User() as item,)):  # type: ignore[misc]
                pass
            case object(collections=(Collection() as item,)):  # type: ignore[misc]
                pass
            case object(documents=(Document() as item,)):  # type: ignore[misc]
                pass
            case _:
                raise ValueError("Updating many is not supported.")

        param: T_Update = self.update_data
        match self.update_data.kind_mapped:
            case KindObject.user | KindObject.collection | KindObject.document:
                param_dict = param.model_dump(exclude_none=True, exclude=exclude)
            case bad:
                msg = f"Incorrect parameter type (got `{bad}` expected "
                msg += f"{KindObject.user}` or `{KindObject.document})."
                raise ValueError(msg)

        # NOTE: @optional will raise 422 if all `null`
        data.event = Event(
            uuid_obj=item.uuid,
            kind_obj=param.kind_mapped,
            detail="Fields updated using `generic_update`.",
            **self.event_common,
        )

        for column, value in param_dict.items():
            setattr(item, column, value)
            data.event.children.append(
                Event(
                    uuid_obj=item.uuid,
                    kind_obj=param.kind_mapped,
                    detail=f"Field `{column}` updated.",
                    **self.event_common,
                )
            )

        if commit:
            session.add(item)
            session.add(data.event)
            session.commit()
            session.refresh(data.event)
            session.refresh(item)

        return data, param  # type: ignore

    # ------------------------------------------------------------------------ #

    def user(self, data: Data[ResolvedUser]) -> Data[ResolvedUser]:
        session = self.session
        data, _ = self.generic_update(data, commit=True)
        user, *_ = data.data.users
        data.event = Event(
            **self.event_common,
            kind_obj=KindObject.collection,
            uuid_obj=user.uuid,
            detail="User updated.",
            children=[data.event],
        )
        session.add(data.event)
        session.add_all(data.data.users)
        session.commit()
        session.refresh(data.event)
        for item in data.data.users:
            session.refresh(item)

        return data

    a_user = with_access(Access.d_user)(user)

    # ------------------------------------------------------------------------ #

    def collection(self, data: Data[ResolvedCollection]) -> Data[ResolvedCollection]:
        param: CollectionUpdateSchema
        token_user = data.token_user or self.token_user
        data, param = self.generic_update(data, {"uuid_user"}, commit=False)

        collection, *_ = data.data.collections
        event_root = data.event
        data.event = Event(
            **self.event_common,
            kind_obj=KindObject.collection,
            uuid_obj=collection.uuid,
            detail="Collection updated.",
            children=[],
        )

        if event_root is not None and event_root.children:
            data.event.children.append(event_root)

        session = self.session
        if param.uuid_user is None:
            return data

        # Transfer ownership, same transaction so easy to rollback.
        collection = data.data.collections[0]
        user = User.if_exists(
            session,
            param.uuid_user,
        )
        collection.id_user = user.id
        data.event.children.append(
            Event(
                **self.event_common,
                kind_obj=KindObject.user,
                uuid_obj=token_user.uuid,
                detail="Ownership of collection transfered.",
            )
        )

        return data

    a_collection = with_access(Access.d_collection)(collection)

    # ------------------------------------------------------------------------ #

    def document(self, data: Data[ResolvedDocument]) -> Data[ResolvedDocument]:
        session = self.session
        # token_user = data.token_user or self.token_user

        param: DocumentUpdateSchema
        data, param = self.generic_update(data, {"content"}, commit=False)
        document = data.data.documents[0]

        if param.content is None:
            session.add(document)
            session.add(data.event)
            session.commit()
            session.refresh(data.event)
            return data

        document.content = param.content

        session.add(data.event)
        session.commit()
        session.refresh(data.event)
        return data

    a_document = with_access(Access.d_document)(document)

    # ------------------------------------------------------------------------ #

    def create_event_grant(
        self, data: DataResolvedGrant, grants_pending: Tuple[Grant, ...]
    ) -> Event:
        grant_uuid_target_key = f"uuid_{data.data.kind_target.name}"
        return Event(
            **(event_common := self.event_common),
            uuid=secrets.token_urlsafe(8),
            uuid_obj=data.data.uuid_source,
            kind_obj=data.data.kind_source,
            children=[
                Event(
                    **event_common,
                    uuid=secrets.token_urlsafe(8),
                    kind_obj=data.data.kind_target,
                    uuid_obj=getattr(grant, grant_uuid_target_key),
                    children=[
                        Event(
                            **event_common,
                            uuid=secrets.token_urlsafe(8),
                            kind_obj=data.data.kind_assoc,
                            uuid_obj=grant.uuid,
                        )
                    ],
                )
                for grant in grants_pending
            ],
        )

    def grant_user(
        self,
        data: Data[ResolvedGrantUser],
    ) -> Data[ResolvedGrantUser]:
        """Allow `token_user` to accept grants for many documents."""

        # NOTE: Pending invitations should not be included in data. This
        #       url should still require the user uuid in the url because admins
        #       will be able to modify permissions generally.
        token_user = data.token_user or self.token_user
        if token_user.uuid != data.data.user.uuid:
            detail = dict(
                msg="User cannot accept grants of other users.",
                uuid_user=data.data.uuid_user,
                uuid_user_token=token_user.uuid,
            )
            raise HTTPException(403, detail=detail)

        pending_grants = data.data.grants
        for grant in (pending_values := pending_grants.values()):
            # NOTE: Aleady checked by access. Here incase errs.
            if grant.pending_from != PendingFrom.grantee:
                raise HTTPException(
                    500,
                    detail="Cannot approve grant pending from `grantee` or `created`.",
                )

            # grant.uuid_parent = token_user_grant.uuid
            # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Assigned by granter on invite
            grant.pending = False
            self.session.merge(grant)

        event = self.create_event_grant(data, tuple(pending_values))
        event.detail = "Access granted."
        data.event = event
        return data

    def grant_document(
        self,
        data: Data[ResolvedGrantDocument],
    ) -> Data[ResolvedGrantDocument]:
        "Granter approves many users for owned doc."

        token_user = data.token_user or self.token_user
        token_user_grant = data.data.token_user_grants[token_user.uuid]

        # Double check the level. The first case should not really happen.
        if token_user.uuid != token_user_grant.uuid_user:
            detail = dict(
                uuid_user=token_user.uuid,
                uuid_user_token_from_grant=token_user_grant.uuid,
                msg="Token user grant is not for token user.",
            )
            raise HTTPException(500, detail=detail)
        elif token_user_grant.level != Level.own:
            detail = dict(
                uuid_user=token_user.uuid,
                uuid_grant=token_user_grant.uuid,
                msg="Grant must be of level `own`.",
                level=token_user_grant.level.name,
            )
            raise HTTPException(500, detail=detail)

        pending_grants = data.data.grants
        for grant in (pending_values := pending_grants.values()):
            if grant.pending_from != PendingFrom.granter:
                raise HTTPException(
                    500,
                    detail="Cannot approve grant pending from `grantee` or `created`.",
                )
            grant.pending = False
            grant.uuid_parent = token_user_grant.uuid
            # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Not assigned when inviting.

        event = self.create_event_grant(data, tuple(pending_values))
        event.detail = "Access granted."
        data.event = event
        return data

    # ------------------------------------------------------------------------ #

    def assignment_document(
        self,
        data: Data[ResolvedAssignmentDocument],
    ) -> Data[ResolvedAssignmentDocument]:
        raise HTTPException(400, detail="Not implemented.")

    def assignment_collection(
        self,
        data: Data[ResolvedAssignmentCollection],
    ) -> Data[ResolvedAssignmentCollection]:
        raise HTTPException(400, detail="Not implemented.")

    # ----------------------------------------------------------------------- #

    def event(self, data: Data[ResolvedEvent]) -> Data[ResolvedEvent]:
        token_user = self.token_user or data.token_user
        (event,) = data.data.events

        event_undo = Event(
            **self.event_common,
            detail="Deletion event reverted.",
            uuid_user=token_user.uuid,  # type: ignore[union-attr]
            kind_obj=KindObject.event,
            uuid_obj=event.uuid,
        )
        event.uuid_undo = event_undo.uuid

        session = self.session
        session.add(event_undo)
        session.add(event)

        for item in event.flattened():
            object_ = item.object_
            if object_ is None or not hasattr(object_, "deleted"):
                continue
            object_.deleted = False

            item.uuid_undo = event_undo.uuid
            session.add(object_)
            session.add(item)

        session.commit()
        session.refresh(event)

        data.event = event_undo
        return data

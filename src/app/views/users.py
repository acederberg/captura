from http import HTTPMethod
from typing import Any, Dict, List, Literal

from app.depends import DependsSessionMaker, DependsToken, DependsTokenOptional
from app.models import Collection, Document, Edit, Event, KindEvent, KindObject, User
from app.schemas import (
    CollectionMetadataSchema,
    DocumentMetadataSchema,
    EditMetadataSchema,
    EventSchema,
    PostUserSchema,
    UserSchema,
    UserSearchSchema,
    UserUpdateSchema,
)
from app.views import args
from app.controllers.access import Access
from app.views.base import BaseView
from fastapi import Depends, HTTPException
from sqlalchemy import false, select, true, update
from sqlalchemy.orm import Session, sessionmaker


class UserView(BaseView):
    """Routes for user data and metadata.

    This will be put on ``/users``.
    """

    view_routes = dict(
        get_users="",
        get_user="/{uuid}",
        patch_user="/{uuid}",
        delete_user="/{uuid}",
        post_user="",
        get_user_documents="/{uuid}/documents",
        get_user_edits="/{uuid}/edits",
        get_user_collections="/{uuid}/collections",
    )

    # ----------------------------------------------------------------------- #
    # READ endpoints.

    # At this point reject bad tokens. A private user should be the
    # only user able to read their own account.
    @classmethod
    def get_user(
        cls,
        sessionmaker: DependsSessionMaker,
        uuid: args.PathUUIDUser,
        token: DependsTokenOptional = None,
    ) -> UserSchema:
        """Get user metadata.

        For instance, this should be used to make a profile page.
        """

        with sessionmaker() as session:
            user = Access(session, token, method=HTTPMethod.GET).user(uuid)
            return user  # type: ignore

    # NOTE: The token depends is included since API billing will depend on
    #       users having a valid token. Later I would like to make it such that
    #       it will also accept requests without tokens from particular
    #       origins, for instance a site where articles may be publicly viewed.
    @classmethod
    def get_users(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        param: UserSearchSchema = Depends(),
    ) -> List[UserSchema]:
        """Get user collaborators or just list some users.

        Once authentication is integrated, getting collaborators will be
        possible. Collaborators will only be possible when the caller has an
        account, otherwise some random users should be returned.
        """
        with sessionmaker() as session:
            if token:
                # Find collaborators.
                ...

            # Get public, active documents.
            uuid_user = None if token is None else token.get("uuid")
            q = User.q_search(
                uuid_user,
                param.uuid_user,
                all_=True,
                name_like=param.name_like,
                description_like=param.description_like,
                session=session,
            )
            return list(UserSchema.model_validate(item) for item in session.execute(q))

    # NOTE: This should not be decorated but should be used in the individual
    #       getters with clearer (not a union) type hints (the ``child``
    #       parameter will not appear in actual endpoints.).
    @classmethod
    def select_user_child(
        cls,
        child: Literal["collections", "edits", "documents"],
        sessionmaker: sessionmaker[Session],
        token: DependsToken,
        uuid_user: args.PathUUIDUser,
    ) -> Any:
        """Get user ``collections`` and ``edits`` data without content.

        :param child: Child to get metadata for. Must be one of ``collections``
            or ``edits``. For ``documents`` use the ``/document`` endpoints.
        :param filter_params: Use these parameters to filter out which children
            to display.
        """

        with sessionmaker() as session:
            access = Access(session, token, method=HTTPMethod.GET)
            user = access.user(uuid_user)
            children: List[Collection] | List[Edit] | List[Document]
            children = getattr(user, child)
            return children  # type: ignore

    # TODO: Test that users can not access other users' private docs/colls from
    #       here.
    @classmethod
    def get_user_documents(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid: args.PathUUIDUser,
        uuid_document: args.QueryUUIDDocumentOptional = None,
    ) -> Dict[str, DocumentMetadataSchema]:
        res = cls.select_user_child(
            "documents",
            sessionmaker,
            token,
            uuid,
        )
        if token["uuid"] != uuid:
            res = {k: v for k, v in res.items() if v.public}
        if uuid_document:
            res = {k: v for k, v in res.items() if k in uuid_document}

        return res

    @classmethod
    def get_user_collections(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid: args.PathUUIDUser,
        uuid_collection: args.QueryUUIDCollectionOptional = None,
    ) -> Dict[str, CollectionMetadataSchema]:
        res = cls.select_user_child("collections", sessionmaker, token, uuid)
        if token["uuid"] != uuid:
            res = {k: v for k, v in res.items() if v.public}
        if uuid_collection:
            res = {k: v for k, v in res.items() if k in uuid_collection}

        return res

    @classmethod
    def get_user_edits(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid: args.PathUUIDUser,
        uuid_edit: args.QueryUUIDEditOptional = None,
    ) -> List[EditMetadataSchema]:
        res = cls.select_user_child(
            "edits",
            sessionmaker,
            uuid,
        )
        if token["uuid"] != uuid:
            res = [item for item in res if item.public]
        if uuid_document:
            res = [item for item in res if item.uuid in uuid_edit]

    # ----------------------------------------------------------------------- #
    # CRUD without R

    @classmethod
    def patch_user(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid: args.PathUUIDUser,
        updates: UserUpdateSchema = Depends(),
    ) -> EventSchema:
        """Update a user.

        Only the user themself should be able to update this.
        """

        with sessionmaker() as session:
            user = Access(session, token).user(uuid)

            # NOTE: Don't forget to include the metadata.
            updates_dict = updates.model_dump()
            event_common = dict(
                uuid_user=token["uuid"],  # use from token incase bad access.
                uuid_obj=uuid,
                kind=KindEvent.update,
                kind_obj=KindObject.user,
                api_origin="PATCH /users/<uuid>",
            )
            event = Event(**event_common, detail="Updated user.")
            for key, value in updates_dict.items():
                if value is None:
                    continue
                setattr(user, key, value)
                event.children.append(
                    Event(**event_common, detail=f"Updated user {key}.")
                )
            session.add(event)
            session.add(user)
            session.commit()
            session.refresh(event)

            return EventSchema.model_validate(event)  # type: ignore

    @classmethod
    def delete_user(
        cls,
        sessionmaker: DependsSessionMaker,
        token: DependsToken,
        uuid: args.PathUUIDUser,
        restore: bool = False,
    ) -> EventSchema:
        """Remove a user and their unshared documents and edits.

        Only the user themself or an admin should be able to call this
        endpoint.
        """

        with sessionmaker() as session:
            user = Access(session, token).user(uuid)
            user.deleted = not restore
            session.add(user)

            # Deactivate exclusive_documents.
            q = user.q_select_documents_exclusive()
            exclusive_documents = list(session.execute(q).scalars())

            event_common = dict(
                uuid_user=uuid,
                kind=KindEvent.delete,
                detail="User deleted.",
                api_origin="DELETE /users/<uuid>",
            )
            event = Event(
                **event_common,
                uuid_obj=uuid,
                kind_obj=KindObject.user,
                # children=[
                #     Event(
                #         **event_common,
                #         uuid_obj=dd.uuid,
                #         kind_obj=KindObject.document,
                #     )
                #     for dd in exclusive_documents
                # ],
            )
            session.add(event)

            # Delete documents
            for dd in exclusive_documents:
                ...

            # Delete collections
            ...

            session.commit()

            return EventSchema.model_validate(event)  # type: ignore

    @classmethod
    def post_user(
        cls,
        sessionmaker: DependsSessionMaker,
        data: PostUserSchema,
    ) -> EventSchema:
        """Create a user.

        For now sharing of collections or documents can be done through
        calling `POST /grant/users/<uuid>/documents/<uuid_document>` endpoints.
        """
        api_origin = "POST /users"
        with sessionmaker() as session:
            session.add(
                user := User(**data.model_dump(exclude={"collections", "documents"}))
            )
            session.commit()
            session.refresh(user)

            events_common = dict(
                uuid_user=user.uuid,
                api_origin=api_origin,
                kind=KindEvent.create,
            )
            session.add(
                event := Event(
                    **events_common,
                    uuid_obj=user.uuid,
                    kind_obj=KindObject.user,
                    detail="User created.",
                )
            )
            session.commit()

            if data.collections:
                session.add_all(
                    collections := [
                        Collection(**cc.model_dump(), id_user=user.id)
                        for cc in data.collections
                    ]
                )

                session.commit()
                session.add_all(
                    [
                        Event(
                            **events_common,
                            uuid_parent=event.uuid,
                            uuid_obj=cc.uuid,
                            kind_obj=KindObject.collection,
                            detail="Collection created.",
                        )
                        for cc in collections
                    ]
                )
                session.commit()
            if data.documents:
                session.add_all(
                    documents := [Document(**dd.model_dump()) for dd in data.documents]
                )
                session.commit()
                user.documents = {dd.name: dd for dd in documents}
                session.add(user)
                session.add_all(
                    [
                        Event(
                            **events_common,
                            uuid_parent=event.uuid,
                            uuid_obj=dd.uuid,
                            kind_obj=KindObject.document,
                            detail="Document created.",
                        )
                        for dd in documents
                    ]
                )
                session.commit()

            session.refresh(event)
            return EventSchema.model_validate(event)

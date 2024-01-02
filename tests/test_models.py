from typing import Any, ClassVar, Dict, List, Self, Type

import pytest
import yaml
from app import util
from app.models import (
    AssocCollectionDocument,
    AssocUserDocument,
    Base,
    Collection,
    Document,
    Edit,
    User,
)
from sqlalchemy import delete, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, make_transient, sessionmaker

logger = util.get_logger(__name__)


class ModelTestMeta(type):
    __children__: ClassVar[Dict[str, "BaseModelTest"]] = dict()

    def __new__(cls, name, bases, namespace):
        if name == "BaseModelTest":
            return super().__new__(cls, name, bases, namespace)

        # M, since it is needed to determine the default dummies file name.
        if (M := namespace.get("M")) is None:
            raise ValueError("`M` must be defined.")
        elif not issubclass(M, Base):
            raise ValueError(f"`{name}.M={M}` must be a subclass of `{Base}`.")

        if (dummies_file := namespace.get("dummies_file")) is None:
            dummies_file = util.Path.test_assets(f"{M.__tablename__}.yaml")
            namespace["dummies_file"] = dummies_file

        # Dummies. Cannot declare dummies directly.
        if namespace.get("dummies") is not None:
            raise ValueError("Cannot specify dummies explicitly.")

        with open(dummies_file, "r") as file:
            namespace["dummies"] = (dummies := yaml.safe_load(file))

        _msg = f"`{name}.dummies_file={dummies_file}`"
        if not isinstance(dummies, list):
            raise ValueError(f"{_msg} must deserialize to a list.")
        elif len(
            bad := tuple(
                index
                for index, item in enumerate(dummies)
                if not isinstance(item, dict)
            )
        ):
            raise ValueError(f"{_msg} has bad entries in positions `{bad}`.")

        T = super().__new__(cls, name, bases, namespace)
        cls.__children__[T.M.__tablename__] = T  # type: ignore
        return T


class BaseModelTest(metaclass=ModelTestMeta):
    # NOTE: This will matter less when the dummy data project is copmlete.
    M: ClassVar[Type[Base]]
    dummies_file: ClassVar[str]
    dummies: ClassVar[List[Dict[str, Any]]]

    @classmethod
    def preload(cls, item):
        return item

    @classmethod
    def clean(cls, session: Session) -> None:
        logger.debug("Cleaning %s.", cls.M.__tablename__)
        for item in session.execute(select(cls.M)).scalars():
            session.delete(item)
        session.commit()

    @classmethod
    def load(cls, session: Session, start: int = 0, stop: int | None = None) -> None:
        logger.debug("Adding %s dummies from `%s`.", cls.M, cls.dummies_file)
        session.add_all(
            list(cls.preload(cls.M(**item)) for item in cls.dummies[start:stop])
        )
        session.commit()


# NOTE: Test suites must be defined in appropraite order to ensure that
#       integrity constraints allow data to be inserted successfully.
class TestUser(BaseModelTest):
    M = User

    @classmethod
    def create_user(cls, session: Session, id: int = 1) -> None:
        """Recreate the user with id :param:`id` and regenerate any associated
        objects for which deletion cascading should apply.


        Documents should not cascade deletion except for documents that user
        is the sole owner of, as stated in **section B.4.a.1**, but the plan
        is to enforce this at the API level. The same applies for the
        :attr:`Edit` objects associated with the document. This
        implies that only the :class:`Collection` objects associated with the
        user must be regenerated along with the user.

        :param session:
        :param id:
        """
        logger.debug("Adding user with id `%s`.", id)
        raw = next((m for m in cls.dummies if m["id"] == 1), None)
        if raw is None:
            raise ValueError(f"Could not find user with id `{id}`.")
        session.add(cls.M(**raw))
        session.commit()

    @classmethod
    def get_user(cls, session: Session, id: int = 1) -> User:
        """Get the :class:`User` with ``User.id`` equal to :param:`id` in the
        provided :param:`session`.

        :param session: database session.
        :param id: `User.id` to match against.
        :raises AssertionError: When the user with the specified :param:`id`
            does not exist.
        :returns: The user.
        """
        user = session.execute(select(User).where(User.id == id)).scalar()
        assert user is not None, f"Expected user with id `{id}`."
        return user

    def make_transient(self, session: Session, user: User):
        """Make the user object and its mapped objects transient.

        This is useful for reinstantiating :class:`User` objects and their
        child objects after deletion with `session.delete`.

        :param session:
        :param user:
        :returns: None
        """
        make_transient(user)
        for collection in user.collections.values():
            make_transient(collection)
        for edit in user.edits:
            make_transient(edit)

    def test_collections_relationship(self, sessionmaker: sessionmaker[Session]):
        logger.debug("Initializing collections.")
        with sessionmaker() as session:
            q_collections = select(Collection)
            collections: List[Collection] = list(
                session.execute(q_collections).scalars()
            )
            assert len(collections), "Collections not found."

            for collection in collections:
                collection.id_user = None  # type: ignore

            session.add_all(collections)
            session.commit()

        logger.debug("Verifying that collections have no owner.")
        with sessionmaker() as session:
            # Check that collections were properly initialized.
            collections = list(session.execute(q_collections).scalars())
            assert len(collections), "Collections not found."
            assert not len(
                list(
                    dict(id=cc.id, id_user=cc.id_user)
                    for cc in collections
                    if cc.id_user is not None
                )
            ), "Collections should not have an owner at this point."

            # Check that user corresponds correctly.
            user = self.get_user(session)
            assert user is not None, "User with id `1` should exist."
            assert not len(user.collections), "User should have no collections."

            # Assign collections
            logger.debug("Assigning collections to user with id `1`.")
            user.collections = {cc.name: cc for cc in collections}
            session.commit()

        logger.debug("Verifying reassignment.")
        with sessionmaker() as session:
            # Check that the ids were reassigned.
            _ = select(Collection)
            collections = list(session.execute(_).scalars())
            assert len(collections), "Collections not found."
            assert not len(
                list(
                    dict(id=cc.id, id_user=cc.id_user)
                    for cc in collections
                    if cc.id_user != 1
                )
            )

        logger.debug("Verifiying deletion cascading.")
        with sessionmaker() as session:
            # NOTE: It is important to get a new user for this session. Things
            #       become strange when this is not done, for instance
            #       ``user.edits`` has null key values after deletion.
            user = self.get_user(session)
            session.delete(user)
            session.commit()

            count = session.execute(
                select(func.count()).select_from(Collection)
            ).scalar()
            assert count == 0

            # NOTE: Do not try to regenerate ownership at the end of these
            #       tests. Most of the tests start by nullifying ownership
            #       anyway. Must regenerate all test collections.
            logger.debug("Regenerating user.")
            self.create_user(session, 1)  # changes are commited
            session.commit()

            TestCollection.load(session)

        logger.debug("Verifying regeneration.")
        with sessionmaker() as session:
            count = session.execute(select(func.count()).where(User.id == 1)).scalar()
            assert count is not None
            assert count > 0, "User with id `1` not regenerated."

            count = session.execute(
                select(func.count()).select_from(Collection)
            ).scalar()
            assert count is not None
            assert count > 0, f"{collections = }"  # type: ignore

    def test_documents_relationship(
        self,
        sessionmaker: sessionmaker[Session],
    ):
        with sessionmaker() as session:
            # NOTE: Initially there should be no documents for the user. Clear
            #       documents for this user out directly through the
            #       association table.
            logger.debug(
                "Clearing existing associations for user sby modifying the "
                "association table directly."
            )
            assocs: List[AssocUserDocument] = list(
                session.execute(
                    select(AssocUserDocument).where(AssocUserDocument.id_user == 1)
                ).scalars()
            )
            for assoc in assocs:
                session.delete(assoc)
            session.commit()

            # NOTE: Verify that the user has no associations after deleting
            #       from the association table.
            logger.debug("Verifying that associations were cleared.")
            user: User = self.get_user(session)
            assert not user.documents, "Expected no documents for users."

            # NOTE: Reassign these documents using the orm.
            logger.debug("Reassigning documents to user 1 using the ORM.")
            documents: List[Document] = list(
                session.execute(
                    q_docs := select(Document).where(Document.id.between(1, 3))
                ).scalars()
            )
            assert len(documents), "Expected to find some documents."
            user.documents = {dd.name: dd for dd in documents}
            session.commit()

        # New session just to be safe
        with sessionmaker() as session:
            logger.debug("Verifying that documents were reassigned.")
            user = self.get_user(session)
            assert user.documents, "Expected documents to be assigned to user."

            # NOTE: Deletion cannot cascade as it would require adding the
            #       access level to the join condition. Deletions of this sort
            #       require additional database operations (verifying that
            #       the deleted user is the sole owner) and therefore the logic
            #       will be placed in API endpoints.
            #
            # NOTE: Required for **section B.4.a.1** for the above reasons.
            #
            logger.debug("Deleting user 1.")
            session.delete(user)
            session.commit()

            logger.debug("Checking that documents were not deleted.")
            documents = list(session.execute(q_docs).scalars())
            assert documents

            self.create_user(session)
            TestCollection.load(session, stop=len(user.collections))

    def test_edits_relationship(self, sessionmaker: sessionmaker[Session]):
        with sessionmaker() as session:
            # NOTE: Initialize edits by nullifying the :class:`Edit`
            #       objects' `user_id` field. Verify that this is consistent
            #       with the user object.
            logger.debug("Initializing edits (no ownership).")
            edits: List[Edit] = list(
                session.execute(select(Edit).where(Edit.id_user == 1)).scalars()
            )
            for edit in edits:
                edit.id_user = None
            session.add_all(edits)
            session.commit()

            user = self.get_user(session)
            assert not user.edits, "Expected no edits."

            # NOTE: Assign edits and commit.
            edits = list(
                session.execute(
                    q_edits := select(Edit).where(Edit.id.between(1, 5))
                ).scalars()
            )
            assert len(edits), "Expected edits."
            user.edits = edits
            session.commit()

        # New session for good measure
        with sessionmaker() as session:
            # NOTE: Verify that the selected edits were asssigned. The user
            #       should be deleted, but id on the edits should havd id_user
            #       nullified.
            #
            # NOTE: See **section B.4.a.1**. The logic required to determine
            #       if a user is a sole owner of a document will happen inside
            #       of api endpoints instead of at the level the ORM. Therefore
            #       deletion should not be cascaded.
            #
            user = self.get_user(session)
            assert len(user.edits) == len(edits)
            session.delete(user)
            session.commit()

            edits = list(session.execute(q_edits).scalars())
            assert len(edits), "Edits should still exist."

            self.create_user(session)
            TestCollection.load(session, stop=len(user.collections))


class TestCollection(BaseModelTest):
    M = Collection

    def get_collection(self, session, id=1) -> Collection:
        m = session.execute(select(Collection).where(Collection.id == id)).scalar()
        if m is None:
            raise AssertionError("Expected collection with id=`{id}`.")
        return m

    # def test_user_optional(self, sessionmaker: sessionmaker[Session]):
    #     assert print(id(sessionmaker))
    #     ...

    def test_user_relationship(self, sessionmaker: sessionmaker[Session]):
        with sessionmaker() as session:
            collection = self.get_collection(session)
            user_initial = collection.user
            user_final = TestUser.get_user(
                session,
                1 + (collection.user.id % 2),
            )
            user_initial_id, user_final_id = user_initial.id, user_final.id
            assert user_final_id != user_initial_id

            collection.user = user_final
            session.commit()

        with sessionmaker() as session:
            collection = self.get_collection(session)
            user_initial = TestUser.get_user(session, user_initial_id)
            user_final = TestUser.get_user(session, user_final_id)
            assert collection.name not in user_initial.collections
            assert collection.name in user_final.collections
            assert collection.id_user == user_final.id

            collection.user = user_initial
            session.add(collection)
            session.commit()

    def test_documents_relationship(self, sessionmaker: sessionmaker[Session]):
        with sessionmaker() as session:
            logger.debug("Manually deassigning documents from collection 1.")
            assocs = list(
                session.execute(
                    select(AssocCollectionDocument).where(
                        AssocCollectionDocument.id_collection == 1
                    )
                ).scalars()
            )
            for assoc in assocs:
                assoc.id_collection = None
            session.add_all(assocs)
            session.commit()

            logger.debug("Verifying that collection 1 has no documents.")
            collection = self.get_collection(session)
            assert not collection.documents, "Expected no documents in collection `1`."

            documents = list(
                session.execute(
                    q_docs := select(Document).where(Document.id.between(1, 4))
                ).scalars()
            )
            collection.documents = {dd.name: dd for dd in documents}
            session.commit()

        with sessionmaker() as session:
            collection = self.get_collection(session)
            assert collection.documents

            session.delete(collection)
            session.commit()

        with sessionmaker() as session:
            # Test deletion, etc
            docs = list(session.execute(q_docs).scalars())
            assert docs


class TestDocument(BaseModelTest):
    M = Document

    @classmethod
    def preload(cls, item: Document) -> Document:
        item.content = bytes(item.content, "utf-8")
        return item

    def get_document(self, session: Session, id: int = 1) -> Document:
        m = session.execute(select(Document).where(Document.id == id)).scalar()
        if m is None:
            raise ValueError(f"Could not find document with id `{id}`.")
        return m

    def test_collection_relation(self, sessionmaker: sessionmaker[Session]):
        """Redundant."""
        with sessionmaker() as session:
            logger.debug("Manually nullifying collections for document `1`.")
            assocs = list(
                session.execute(
                    select(AssocCollectionDocument).where(
                        AssocCollectionDocument.id_document == 1
                    )
                ).scalars()
            )
            for assoc in assocs:
                session.delete(assoc)
            session.commit()

            logger.debug("Verifying that document `1` has no collections.")
            document = self.get_document(session)
            assert (
                not document.collections
            ), "Expected document `1` to have no collections."

            logger.debug("Assigning collections for document `1`.")
            collections: List[Collection] = list(
                session.execute(
                    q_collections := select(Collection).where(
                        Collection.id.between(1, 5)
                    )
                ).scalars(),
            )
            assert (
                n_collections := len(collections)
            ) > 0, "Expected to find collections."
            document.collections = {cc.name: cc for cc in collections}
            session.commit()

        with sessionmaker() as session:
            document = self.get_document(session)
            assert len(document.collections) == n_collections

            # NOTE: Deleting the collection should not delete the document. See
            #       **section B.4.b**.
            session.delete(document)
            session.commit()

            collections = list(session.execute(q_collections).scalars())
            assert len(collections) == n_collections, (
                f"Expected `{n_collections}` results from execution of "
                "`q_collections`."
            )

            make_transient(document)
            session.add(document)
            session.commit()

    def test_edits_relationship(self, sessionmaker: sessionmaker[Session]):
        with sessionmaker() as session:
            document = self.get_document(session, 6)
            assert len(document.edits) > 1, "Expected edits for document 6."

        with sessionmaker() as session:
            edit_ids: List[int] = list(edit.id for edit in document.edits)

            session.delete(document)
            session.commit()

            q = select(Edit.id)
            q = q.where(Edit.id.in_(edit_ids))
            edit_ids_final = list(session.execute(q).scalars())
            assert not edit_ids_final, "Expected no edits for document `6`."


# NOTE: Other sides of relationships tested. Not going to bother testing as a
#       result.
class TestEdit(BaseModelTest):
    M = Edit

    @classmethod
    def preload(cls, item: Edit) -> Edit:
        item.content = bytes(
            item.content,
            "utf-8",
        )  # type: ignore
        return item


class TestAssocUserDocument(BaseModelTest):
    M = AssocUserDocument

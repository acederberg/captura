Running in Docker
===============================================================================

A docker compose project is included so that it is easy to get a database up
and running. It does not cache dependencies since your local work is mounted,
which should include a python virtual environment. The steps are as follows:

.. code:: python

   # Spin up venv on your machine and install the project
   python -m venv .venv
   source .venv/bin/activate
   pip install --editable .

   # Start the docker compose project.
   docker compose --file=docker/docker-compose.yaml up --detach
   docker compose --file=docker/docker-compose.yaml exec bash

   # Commands inside docker
   source .venv/bin/activate
   app version


Database Schema
===============================================================================

The database should have, as of now, only four tables:

- **Users**. A list of user profiles. These should not contain credentials,
  authentication will be outsourced to `Auth0`.
- **Collections**. These should be collections of individual documents. Some
  collections will belong to a user where others will not.
- **Documents**. Should contain the documents belonging to possibly many
  collections. Documents should be modifyable, and updates will be logged in
  `DocumentHistories`. A document should belong to one or many users, with
  the initial user being given admin permissions.
- **DocumentHistories**. A log of updates to a document.


API Endpoint Rubric
===============================================================================

A. Definitions
-------------------------------------------------------------------------------

1. A **user** (equivilently ``User``) is the database entry in the ``users``
   table that will be determined by a ``JSON`` web token.

2. A user **owns** a ``Collection`` when the collections ``id_user`` field is
   the user id, but owns a ``Document`` only when a ``AssocUserDocument`` entry
   associates the document and the user AND specifies the ``owner`` permission.


B. Specifications
-------------------------------------------------------------------------------

1. Reading:
   a. Endpoints should exist for reading objects and their associated objects.
      For instance ``Edit`` objects should be available on ``Document`` and
      ``User`` objects (respectively these will be the edits on a ``Document``
      or by a particular ``User``).
   b. Private ``Document`` objects should not be able to be viewed unless the
      correct permissions are granted, see **section B.3.a.1**.
   c. The ``DocumentHistory`` objects associated of with a private ``Document``
      should follow the same read rules as **section B.1.b**. Note that
      document histories may not be updated or deleted, only read.
   d. Private ``Collection`` should only be viewable by their owners.
   e. There should be an endpoint to read documents that belong to no
      ``Collection`` objects.

2. Creation:
   a. When a ``Document`` object is posted, there should be an option to
      specify which users can access it and which ``Collection`` it belongs to.
      By default, all new documents will be private until they are publicly
      readable.
   b. User creation can include new ``Document`` and ``Collection`` objects.
      This would make a nice "sign up" flow in a user interface. Creation of
      the associated document should include the options specified in
      **section B.2.a**.
   c. When a ``Collection`` object is posted, there should be an option to
      specify if it is private or not.
   d. ``DocumentHistory`` entries cannot be directly posted. Instead, they will
      be created when an upate to a document is posted. See **section B.3.d**
      (about edits to ``DocumentHistory`` objects) and **section B.3.g**.

3. Updates:
   a. Permissions cannot be managed through/on ``Collection`` objects.
      Permissions should only be managed between users and documents.
      1. ``Collection`` objects can be private, but in such a case they can
         only be managed by their owner (see section A.1 and B.1.d).
   b. Only authorized users (document owners) should have access to update
      and delete their respective documents. Owners should be able to grant
      this access to other users by creating entries in the association table
      from ``Document`` to ``User`` using some endpoint to specify the level.
      1. When the article is public, adding read permissions will not change
         anything - otherwise the user granted these permissions will be able
         to view the document.
      2. The available permission levels should be ``read``, ``write``, and
         ``owner``. ``NULL`` permissions on a document for a user will imply no
         permissions, meaning that it can only be read when it is private.
   c. Only (document owners) should have access to update the collections to
      which a document belongs.
   d. No updates for ``DocumentHistory`` objects.
   e. No updates for the ``name`` field of ``Collection`` and ``User`` objects.
   f. No bulk updates.
   g. When a ``Document`` object is updated, its content is stored as a
      ``DocumentHistory`` entry.

4. Deletion:
   a. When a user is soft deleted (hidden),
      1. The ``Document`` objects will also be soft deleted when the user is
         the SOLE OWNER. The edits to these documents will be hard deleted.
      2. Edits to documents not owned by the user will be preserved and
         continue to use the username to display the edits.

      To reiterate, when a user is hard deleted, the ``DocumentHistory``
      entries associated with it should not be deleted except for articles for
      which the user is the sole owner.
   b. ``Collection`` objects should not cascade soft deletion to the associated
      ``Document`` objects.
      1. In the case that document has all of its ``Collection`` objects
         deleted, the document will belong to no collections. This implies that
         it would be useful to be able to read such documents, see
         **section B.1.e**.
   c. No bulk deletions.

In sumary,

``DocumentHistory`` objects cannot be created directly and cannot be destroyed.
They are created when a ``Document`` is updated.

Permissions do not exist for ``Collection`` objects, but are defined entirely
through ``AssocUserDocument`` objects. Only an owner of a ``Document`` object
should be able to determine the ``Collection`` objects associated with a
``Document``, and only owners should be able to grant permissions on it.

``User`` objects own ``DocumentHistory``, ``Document``, and ``Collection``
objects, but can only make ``Collection`` objects public/private, however
``Document`` objects may be shared with other users (for reading, writing, or
ownership) when private, when public anybody can read.

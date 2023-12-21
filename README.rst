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

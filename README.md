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

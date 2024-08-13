What Does This Do?
###############################################################################

The goals of captura are the following:

A. As a Base for/Enhancement of other apps:

   1. Extensibility using plugins. For instance, setting a schema for the 
      ``content`` sections of any of the 'first class' tables or adding 
      additional granting functionality.
   2. Make it easy to add sharing between application users to existing 
      services. This is done using the ``content`` sections of the various 
      tables where users can choose how to shape their data.

B. Control of Permissions and Visibility:

   1. Delegate various levels of permissions in sharing, e.g. ``view``, 
      ``modify``, or ``own``. ``documents`` can be public or private.
   2. Organize ``documents`` into ``collections`` and ``collections`` in 
      ``collections``.

C. Emmit events for those who desire them.


Installation
###############################################################################

See the next section.


For Those Who Want to Contribute/Modify/Run
###############################################################################

First, ``git clone`` this project and go to the cloned directory. Then run 

.. code:: sh

  mkdir ./configs ./logs



Starting Docker
===============================================================================

A docker compose project is included so that it is easy to get a server and 
database up and running. The defaults included in ``./src/app/config.py`` will 
work for the compose projects mysql instance. To start the compose project do

.. code:: python

   # Start the docker compose project.
   docker compose --file=docker/docker-compose.yaml up --detach
   docker compose --file=docker/docker-compose.yaml exec bash


and then

.. code:: bash

   python -m venv .venv
   source .venv/bin/activate 
   python -m pip install --editable .


and then create your application configuration.


Configuration
===============================================================================

Captura is built with configurability in mind. All configuration can be written
using ``YAML`` or ``JSON``. Configuration is by default contained in the 
``./configs`` directory, but the locations (paths of) of these configurations 
can be set using 

- ``CAPTURA_CONFIG_APP``
- ``CAPTURA_CONFIG_CLIENT``
- ``CAPTURA_LOG_CONFIG``


To see if these are set as desired, using the captura command as follows:

.. code:: bash

   captura config --envvars



Captura Server
-------------------------------------------------------------------------------

There are a few important pieces of information that captura will require to 
run the compose project. A minimal configuration should look something like 
this:

.. code:: yaml

   # ./configs/app.yaml

   auth0: 
     use: False
     issuer: auth.example.org 
     registration_code_salt: <big nasty string>
     api:
       audience: example.com
     app:
       client_id: <big nasty string>
       client_secret: <big nasty string>
   mysql: {}
   app:
     environment: development
     host_scheme: http://


This configuration can be validated using the following command:

.. code:: bash

   captura config


This will generate an error that can guide you on how to configure the app if 
the configuration is malformed. Otherwise, your configuration will be printed
(with sensored secrets thanks to pydantic) to the terminal. 

Once your configuration is valid then ensure that captura will run:

.. code:: bash

   captura run


Client 
-------------------------------------------------------------------------------

This clients configuration is inspired by ``kubectl``. This is because when 
using kubernetes I found it extermely convenient to be able to switch out this 
host used without directly editting configuration. 

The following instructions require that captura is not run in auth0 mode. To
do so run 

.. code:: bash

   CAPTURA_AUTH0__USE=false captura run


this will make it such that test tokens can be generated using captura itself. 
DO NOT USE PYTEST MODE IN PRODUCTION! ANYBODY CAN MAKE TOKENS IF THEY DESIRE TO!
To create your first token do:

.. code:: bash

   legere tokens register \
     --name "example" \
     --description "example" \
     --url "example.com" \
     --email "example@example.com"


For subsequent tokens use ``legere tokens create``. With this token, create 
a client configuration. A minimal configuration should look like

.. code:: yaml
   
   # ./config/client.yaml
   hosts:
     docker_self:
       host: http://localhost:8080
       remote: true  # Requires that ``captura run`` is invoked in the container
     docker_hostless:
       host: http://localhost:8080
       remote: false   # Client uses an app instance directly.
   profiles: 
     docker_self:
       token: *************
       remote: true
   use: 
     host: docker_self
     profile: docker_self


and can be validated as follows:

.. code:: bash

   legere config show

   # List the hosts configured
   legere config hosts --all

   # List the profiles configured
   legere config profiles --all
    
   # Change the host
   legere config use --host docker_hostless


To use the client on the docker host (instead of in the container, as above)
install this project and run:

.. code:: 

   # Get the host into client.yaml
   legere config docker-host --config-out configs/client.yaml

   # Use this host by default 
   legere config use --host docker --config-out ./configs/client.yaml

   # Verify
   legere config show


Finally, the output format may be configured: 

.. code:: yaml

   ...
   output:
     decorate: false
     output: yaml
     output_fallback: json
     rich_theme: fruity




Dummy
-------------------------------------------------------------------------------

You probably won't need dummies. If you do, add 

.. code:: yaml

   dummies:
     dummy:
       collections:
         minimum: 4
         maximum: 8
       documents:
         minimum: 9
         maximum: 16
       grants:
         minimum_self: 25
         maximum_self: 36
         minimum_other: 25
         maximum_other: 36
       users:
         minimum: 75
         maximum_uses: 100

to your application configuration and configure it to your liking. This
configuration may be validated like

.. code:: bash

   simulatus preview


and controls the ``simulatus`` command, which can be used to assess the database
as a whole or per user and debug assist in debugging of tests.
 


Database Schema
===============================================================================

The database only requires six tables for the time being:

- **Users**. A list of user profiles. These should not contain credentials,
  authentication will be outsourced to `Auth0`.
- **Collections**. These should be collections of individual documents. Some
  collections will belong to a user where others will not.
- **Documents**. Should contain the documents belonging to possibly many
  collections. Documents should be modifyable, and updates will be logged in
  `DocumentHistories`. A document should belong to one or many users, with
  the initial user being given admin permissions.
- **Grants**. Associtions between users and documents.
- **Assignments**. Associtions between collections and documents.
- **Events**. Eventually this will be used to stream events.
- **Demos**. This is to have a record of who has requested a demo. This will 
  eventually be a plugin and therefore this table will be optional.

Other tables may be added by plugins or other parts of the code. For instance, 
the ``dummy`` module will require the ``reports`` and ``reports_grants`` table.

For Those Who Wish to use the API
###############################################################################

Captura's database model is designed to make it easy to layer on top of 
existing services - essentially the goals are the following:


Getting Started
===============================================================================

Demo App
-------------------------------------------------------------------------------

First of all, request a demo at ``captura.acederberg.io/demo``. An admin will
likely accept your demo account if you are not a bot. 

After your demo account is created, create your account by going to ``/login``. 
This will allow you to customize your user to your liking. After this, you will 
be redirected to your profile where you can obtain an authorization token.

Using this token, your client configuration should look something like:


.. code:: yaml 

   # ~/.captura/client.yaml

   hosts:
     production:
       host: https://captura.acederberg.io
       remote: true
   profiles:
     production:
       token: <TOKEN FROM ABOVE STEP>
   use:
     host: production
     profile: production



Dockerized App
-------------------------------------------------------------------------------

If you don't want to run and configure your own instance, follow the steps 
above. If you really want to go this way, see ``Installation``. 


Granting Process
===============================================================================

Grants can be initiated two ways: by owners inviting others and acceptance of
invitations by these others, or by non-owners requesting a level of access and
an owner accepting their request.

Owner Grants Access and Grantee Accepts.
-------------------------------------------------------------------------------

Document owner invites others. If pending grants exist, the invitations (in the
form of events) are not recreated. If the grants are deleted and pending
deletion, then adding the `force` parameter will be necessary.

.. code:: sh

   client --profile granter grant documents create --uuid-user $UUID_USER $UUID_DOCUMENT


A user can read their own invitations like


.. code:: sh

   client --profile grantee \
      grants users read \
      --pending $UUID_USER



Either of these will return an array of pending grants. A user can accept an
invitation by sending a patch with grant uuids obtained from the above
requests:

.. code:: sh

   client --profile grantee grants users accept --uuid-grant $UUID_GRANT $UUID_USER


Grantee Requests and Owner Requests
-------------------------------------------------------------------------------

A user can ask for a grant to many (only public) documents like

.. code:: sh

   client --profile grantee grants users --uuid-document $UUID_DOCUMENT $UUID_USER


Note that ``UUID_USER`` must be the uuid of the grantee. Only admins can request
grants for users besides their own. The document holder can then view their
pending grants:

.. code:: sh

   client --profile granter grants documents read --pending $UUID_DOCUMENT

which will return the pending grants. From this a granter can obtain grant
uuids and accept it:

.. code:: sh

   client --profile grantee grants documents accept $UUID_GRANT




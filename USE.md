
Get a token
-------------------------------------------------------------------------------

Make sure that the application is running in pytest mode when creating your own
tokens using this method by doing the following:

.. code:: sh

    # Get a token, strip the '"'s from the JSON string.
    export TOKEN=$( \
        curl '$SERVER_IP_ADDR:8080/auth/token' \
            -X POST \
            -H "Content-Type: Application/JSON" \
            --data '{"uuid": "1meGbogsgf4"}' \
        | sed 's/"//g'
    )


Getting Data Scoped by User
===============================================================================

Data About User(s)
-------------------------------------------------------------------------------

One may ``GET`` a selection of users from the `/user` endpoint. To get
information scoped by a particular user, ``GET /user/{uuid}``. For instance:

.. code:: sh

    curl '$SERVER_IP_ADDR:8080/users' -H "Authorization: Bearer $TOKEN"

This will get you something like the following data:

.. code:: STDOUT

    [
        {
            "uuid": "l9h96gNUwi8",
            "name": "you're mom",
            "description": "The joke is that it is mispelled.",
            "url_image": null,
            "url": null
        },
        {
            "uuid": "1meGbogsgf4",
            "name": "acederberg",
            "description": "maintainer of this project",
            "url_image": "https://avatars.githubusercontent.com/u/77076023?v=4",
            "url": "github.com/acederberg"
        }
    ]


The `/user` endpoint can specify a specific id if necessary:

.. code:: sh

    curl '$:8080/users/l9h96gNUwi8' -H "Authorization: Bearer $TOKEN"


.. code:: STDOUT

    {
        "uuid": "l9h96gNUwi8",
        "name": "you're mom",
        "description": "The joke is that it is mispelled.",
        "url_image": null,
        "url": null
    }

The various items owned by users can be queried like

.. code:: sh

    curl '$SERVER_IP_ADDR:8080/users/1meGbogsgf4/collections' \
        -H "Authorization: Bearer $TOKEN"


.. code:: sh

    {
        "Chicharon.": {
            "uuid": "OC3kyt8O-KY",
            "description": "A collection about New Mexican food."
        }
    }


A new user may be created like:

.. code:: sh

    curl "$SERVER_IP:8080/users" \
        -X POST -H "Authorization: Bearer $TOKEN" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: Application/JSON" \
        -d '{
            "name": "yourGodsGodsGod",
            "description": "A gamertag."
        }'


updated like

.. code:: sh

     curl "$SERVER_IP:8080/users/l9h96gNUwi8?description=sperm%20whale" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: Application/JSON" \
        -X PATCH


and deleted like

.. code:: sh

    curl "$SERVER_IP:8080/users/ChinybYLuCQ" \
        -H "Authorization: Bearer $TOKEN" \
        -X DELETE

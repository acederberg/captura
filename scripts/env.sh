# NOTE: This script must be sourced before the other scripts. Many of the other
#       Many of these scripts show up in ``USE.md``.
#
#       This mostly exists so that I can play with stuff in the terminal
#       before adding the typer client.
#
if [[ ! $SERVER_NAME ]]; then
  echo "Getting server container name."
  export SERVER_NAME=$( \
      docker compose --file=docker/docker-compose.yaml \
      ps --format '{{ .Name }}' \
      | grep server \
  )
else echo "Server container name already known."
fi

if [[ ! $SERVER_IP ]]; then
  echo "Determining IP for \`$SERVER_NAME\`."
  export SERVER_IP=$( \
    docker inspect \
      --format='{{ .NetworkSettings.Networks.docker_documents.IPAddress }}' \
      $SERVER_NAME \
    )
else echo "Server IP already known."
fi

if [[ ! $TOKEN ]]; then
  echo "Getting a token..."
  export TOKEN=$( \
    curl -X POST "$SERVER_IP:8080/auth/token" \
      -H "Content-Type: Application/JSON" \
      --data '{"uuid": "00000000"}' \
    | sed 's/"//g' \
  )
else echo "Token already exists."
fi


export HEADER_TOKEN="Authorization: Bearer $TOKEN" \
  HEADER_CONTENT="Content-Type: Application/JSON" \
  SERVER_ADDR="http://$SERVER_IP:8080"


# NOTE: Only add these on an `as needed` basis, e.g. requests that are
#       frequently used.`

# Get users.
#
# 1. (Optional) A user UUID for a particular user if necessary.
get_users()
{
  echo "Getting users."
  if [[ ! $1 ]]; then export URL="/users"; else export URL="/users/$1"; fi
  curl -X GET -H $HEADER_TOKEN -H $HEADER_CONTENT "$SERVER_ADDR$URL" \
    | python -m json.tool
}


# Get documents for a user.
#
# 1. (Required) The user UUID to get documents for.
get_documents()
{
  echo $1
  if [[ ! $1 ]]; then echo "An argument for the user uuid is required."; return 1; fi
  echo "Getting documents for \`$1\`."
  curl -X GET -H $HEADER_TOKEN -H $HEADER_CONTENT "$SERVER_ADDR/users/$1/documents" \
    | python -m json.tool
}


patch_document_access()
{
  uuid_target=$1
  uuid_document=$2
  level=$3

  if [[ ! $uuid_target ]]; then echo "A user uuid is required."; return 1; fi
  if [[ ! $uuid_document ]]; then echo "A document uuid is required."; return 2; fi
  if [[ ! $level ]]; then level=owner; fi

  URL="/users/$uuid_target/grant?level=$level&uuid_document=$uuid_document"
  echo $SERVER_ADDR$URL
  curl -X PATCH  -H $HEADER_TOKEN -H $HEADER_CONTENT "$SERVER_ADDR$URL" \
    | python -m json.tool


}


deactivate_env()
{
  unset TOKEN SERVER_NAME SERVER_IP HEADER_TOKEN HEADER_CONTENT SERVER_ADDR
  unset -f get_users
}

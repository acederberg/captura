import uvicorn

from . import __version__, util, views

logger = util.get_logger(__name__)


def main():
    """This function can be run by invoking this module (e.g. python -m app)
    or by using the command installed by ``pyproject.toml``, ``app``.

    Soon this will be depricated as typer convenience functions will be added.

    To connect to the application when it is running in the docker compose
    project, run the following:

    .. code:: shell

        # List the processes so that name of the container running this code
        # is known
        export CONTAINER_NAME=$( \
            docker compose --file=docker/docker-compose.yaml \
            ps --format '{{ .Name }}' \
            | grep server \
        )
        export FORMAT='{{ .NetworkSettings.Networks.docker_documents.IPAddress }}'  
        export CONTAINER_IP=$( docker inspect --filter=FORMAT $CONTAINER_NAME )
        curl "http://$CONTAINER_IP:8080"

    """
    logger.info("Running articles server version `%s`.", __version__)
    uvicorn.run(
        "app.views:AppView.view_router",
        port=8080,
        host="0.0.0.0",
        reload=True,
    )


if __name__ == "__main__":
    main()

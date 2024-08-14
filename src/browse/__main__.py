# --------------------------------------------------------------------------- #
from browse import app as app_browse

if __name__ == "__main__":

    # NOTE: About changing this into an app served by uvicorn, see
    #
    # .. code:: python
    #
    #    https://flask.palletsprojects.com/en/2.3.x/async-await/
    #
    # .. code:: python
    #
    #    print("Running via uvicorn")
    #    uvicorn.run(
    #        "browse:app",
    #        reload=True,
    #        reload_dirs=util.Path.base("src/browse"),
    #    )

    app_browse.run(
        debug=True,
        dev_tools_hot_reload=True,
        dev_tools_props_check=True,
    )

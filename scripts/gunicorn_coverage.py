print("Currently commented out.")
# """Use
#
# .. code:: shell
#
#     gunicorn \
#         -c ./tests/gunicorn_coverage.py \
#         -k uvicorn.workers.UvicornWorker \
#         app:app
#
# """
#
# # NOTE: Inspired by
# #
# #       - https://stackoverflow.com/questions/50689940/how-to-generate-coverage-report-for-http-based-integration-tests
# #       - https://github.com/nedbat/coveragepy/issues/1346
# #
# import typer
#
# # --------------------------------------------------------------------------- #
# from app import util
#
# try:
#     import coverage
# except ImportError as err:
#     util.CONSOLE_APP.print(
#         "[red]Missing `coverage` module. Try to install test "
#         "dependencies using `pip install .[test]`."
#     )
#     raise typer.Exit(1) from err
#
# logger = util.get_logger(__name__)
# logger.warning("Running in coverage mode, not reloading!")
# logger.info("Starting coverage collection.")
#
# cov = coverage.coverage()  # type: ignore
# cov.start()
#
#
# # --------------------------------------------------------------------------- #
# from app.views import AppView
#
# app = AppView.view_router  # type: ignore
#
#
# def stop_coverage():
#     cov.stop()
#     cov.save()
#     logger.info("Done collecting coverage.")

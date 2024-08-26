# workaround for ruff removing fixture imports
# they look unused because of dependency injection by pytest
from test_fixtures import *  # noqa


def pytest_addoption(parser):
    parser.addoption(
        "--halmos-options",
        metavar="OPTIONS",
        default="",
        help="Halmos commandline options",
    )

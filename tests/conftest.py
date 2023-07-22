def pytest_addoption(parser):
    parser.addoption(
        "--halmos-options",
        metavar="OPTIONS",
        default="",
        help="Halmos commandline options",
    )

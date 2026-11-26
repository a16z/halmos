from dolmos.build import parse_devdoc, parse_natspec


def devdoc(**tags):
    return {"metadata": {"output": {"devdoc": {"methods": {"f()": tags}}}}}


def test_parse_natspec_dolmos_tag():
    assert parse_natspec({"text": "@custom:dolmos --loop 4"}) == "--loop 4"


def test_parse_natspec_legacy_halmos_tag():
    # test suites written for halmos keep working
    assert parse_natspec({"text": "@custom:halmos --loop 4"}) == "--loop 4"


def test_parse_natspec_both_tags():
    text = "@title T\n@custom:halmos --loop 4\n@notice n\n@custom:dolmos --width 2"
    assert parse_natspec({"text": text}).split() == ["--loop", "4", "--width", "2"]


def test_parse_natspec_other_tags_ignored():
    assert parse_natspec({"text": "@custom:other --loop 4"}) == ""


def test_parse_devdoc():
    assert parse_devdoc("f()", devdoc(**{"custom:dolmos": "--loop 4"})) == "--loop 4"
    assert parse_devdoc("f()", devdoc(**{"custom:halmos": "--loop 4"})) == "--loop 4"
    assert (
        parse_devdoc(
            "f()", devdoc(**{"custom:halmos": "--loop 4", "custom:dolmos": "--width 2"})
        )
        == "--width 2 --loop 4"
    )
    assert parse_devdoc("f()", devdoc()) is None
    assert parse_devdoc("g()", devdoc()) is None

import pytest

from z3 import BitVec

from halmos.cheatcodes import (
    Prank,
    PrankResult,
    NO_PRANK,
    hevm_cheat_code,
    halmos_cheat_code,
)


@pytest.fixture
def prank():
    return Prank()


@pytest.fixture
def sender():
    return BitVec("sender", 160)


@pytest.fixture
def origin():
    return BitVec("origin", 160)


@pytest.fixture
def other():
    return BitVec("other", 160)


def test_prank_truthiness(sender, origin):
    assert not Prank()
    assert Prank(PrankResult(sender=sender))
    assert Prank(PrankResult(origin=origin))
    assert Prank(PrankResult(sender=sender, origin=origin))


def test_prank_can_not_override_active_prank(prank, sender, origin):
    active_prank = PrankResult(sender=sender)

    # when we call prank() the first time, it activates the prank
    assert prank.prank(sender)
    assert prank.active == active_prank

    # when we call prank() the second time, it does not change the prank state
    assert not prank.prank(sender)
    assert prank.active == active_prank

    # same with startPrank
    assert not prank.startPrank(sender, origin)
    assert prank.active == active_prank
    assert not prank.keep


def test_start_prank_can_not_override_active_prank(prank, sender, origin, other):
    active_prank = PrankResult(sender=sender, origin=origin)

    assert prank.startPrank(sender, origin)
    assert prank.active == active_prank
    assert prank.keep

    # can not override active prank
    assert not prank.startPrank(other, other)
    assert prank.active == active_prank
    assert prank.keep


def test_stop_prank(prank, sender, origin):
    # can call stopPrank() even if there is no active prank
    assert prank.stopPrank()
    assert not prank.keep
    assert not prank

    # when we call prank(), the prank is activated
    prank.prank(sender)
    assert prank.active == PrankResult(sender=sender)
    assert not prank.keep

    # when we call stopPrank(), the prank is deactivated
    prank.stopPrank()
    assert not prank
    assert not prank.keep

    # when we call startPrank(), the prank is activated
    prank.startPrank(sender, origin)
    assert prank.active == PrankResult(sender=sender, origin=origin)
    assert prank.keep

    # when we call stopPrank(), the prank is deactivated
    prank.stopPrank()
    assert not prank
    assert not prank.keep


def test_lookup_no_active_prank(prank, other):
    # when we call lookup() without an active prank, it returns NO_PRANK
    assert prank.lookup(other) == NO_PRANK
    assert prank.lookup(hevm_cheat_code.address) == NO_PRANK
    assert prank.lookup(halmos_cheat_code.address) == NO_PRANK


def test_prank_lookup(prank, sender, other):
    # when calling lookup() after prank()
    prank.prank(sender)
    result = prank.lookup(other)

    # then the active prank is returned
    assert result.sender == sender
    assert result.origin is None

    # and the prank is no longer active
    assert not prank


def test_startPrank_lookup(prank, sender, origin, other):
    # when calling lookup() after startPrank()
    prank.startPrank(sender, origin)
    result = prank.lookup(other)

    # then the active prank is returned
    assert result.sender == sender
    assert result.origin == origin

    # and the prank is still active
    assert prank

import pytest
from z3 import BitVec

from halmos.cheatcodes import (
    NO_PRANK,
    Prank,
    PrankResult,
    halmos_cheat_code,
    hevm_cheat_code,
)
from halmos.sevm import CallContext, Message


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
    # setup an active prank
    prank.prank(sender)

    # when calling lookup(to=<cheat-address>)
    for cheat_code in [hevm_cheat_code, halmos_cheat_code]:
        result = prank.lookup(cheat_code.address)

        # then the active prank is ignored
        assert result == NO_PRANK
        assert prank  # still active

    # finally, when calling lookup(to=other)
    result = prank.lookup(other)

    # then the active prank is returned
    assert result.sender == sender
    assert result.origin is None

    # and the prank is no longer active
    assert not prank


def test_startPrank_lookup(prank, sender, origin, other):
    # setup an active prank
    prank.startPrank(sender, origin)

    # when calling lookup(to=<cheat-address>)
    for cheat_code in [hevm_cheat_code, halmos_cheat_code]:
        result = prank.lookup(cheat_code.address)

        # then the active prank is ignored
        assert result == NO_PRANK
        assert prank  # still active

    # finally, when calling lookup(to=other)
    result = prank.lookup(other)

    # then the active prank is returned
    assert result.sender == sender
    assert result.origin == origin

    # and the prank is still active
    assert prank


def test_prank_in_context(sender, origin):
    """
    This is part test and part documentation.

    It implements the intended handling of messages, contexts and pranks by sevm,
    and it shows the expected flow of values from prank creation to consumption.
    """

    pranked_sender = BitVec("pranked_sender", 160)
    pranked_origin = BitVec("pranked_origin", 160)
    CALL = 0xF1

    # start with a basic context
    context = CallContext(
        message=Message(
            target=BitVec("original_target", 160),
            caller=sender,
            origin=origin,
            value=0,
            data=b"",
            call_scheme=CALL,
        )
    )

    assert not context.prank

    # a call to vm.prank() would mutate the context's active prank
    context.prank.prank(pranked_sender, pranked_origin)

    # the context now has an active prank
    assert context.prank

    # when creating a sub-context (e.g. for a new call), the prank should be consumed
    call1_target = BitVec("call1_target", 160)
    call1_prank_result = context.prank.lookup(call1_target)
    sub_context1 = CallContext(
        message=Message(
            target=call1_target,
            caller=call1_prank_result.sender,
            origin=call1_prank_result.origin,
            value=0,
            data=b"",
            call_scheme=CALL,
        )
    )

    assert not context.prank
    assert sub_context1.message.caller == pranked_sender
    assert sub_context1.message.origin == pranked_origin

    # the sub-context should have no active prank
    assert not sub_context1.prank

    # subcalls do inherit the origin from the parent context
    call2_target = BitVec("call2_target", 160)
    assert not context.prank.lookup(call2_target)
    sub_context2 = CallContext(
        message=Message(
            target=call2_target,
            caller=sub_context1.message.target,
            origin=sub_context1.message.origin,
            value=0,
            data=b"",
            call_scheme=CALL,
        ),
    )

    assert not sub_context2.prank
    assert sub_context2.message.caller == sub_context1.message.target  # real
    assert (
        sub_context2.message.origin == sub_context1.message.origin
    )  # pranked (indirectly)

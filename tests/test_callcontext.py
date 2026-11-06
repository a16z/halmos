from copy import deepcopy

from halmos.bytevec import ByteVec
from halmos.config import default_config
from halmos.sevm import CallContext, CallOutput, Message, StorageWrite
from halmos.traces import config_context, rendered_trace
from halmos.utils import EVM, con, con_addr


def test_call_context_copy_isolates_active_state_and_preserves_history():
    address = con_addr(0x1234)
    message = Message(
        target=address,
        caller=address,
        origin=address,
        value=con(0),
        data=ByteVec(b"abcd"),
        call_scheme=EVM.CALL,
    )
    write = StorageWrite(address, con(1), con(2), False)
    completed = CallContext(
        message=message,
        output=CallOutput(data=ByteVec(b"result"), return_scheme=EVM.RETURN),
        depth=2,
        trace=[write],
    )
    parent = CallContext(message=message, trace=[completed])
    parent.prank.startPrank(con_addr(0x5678))
    parent.output.accounts_to_delete.add(address)
    branch = parent.copy()
    reference = deepcopy(parent)

    token = config_context.set(default_config())
    try:
        assert rendered_trace(branch) == rendered_trace(reference)
        branch.trace.append(write)
        branch.message.data[0] = 0
        branch.prank.stopPrank()
        branch.output.data = ByteVec(b"branch")
        branch.output.accounts_to_delete.clear()

        assert rendered_trace(parent) == rendered_trace(reference)
        assert parent.message.data.unwrap() == b"abcd"
        assert parent.prank
        assert parent.output.data is None
        assert parent.output.accounts_to_delete == {address}
        assert len(parent.trace) == 1
        assert completed.output.data.unwrap() == b"result"
    finally:
        config_context.reset(token)

# SPDX-License-Identifier: AGPL-3.0

import io
import sys
from contextvars import ContextVar

from z3 import Z3_OP_CONCAT, BitVecNumRef, BitVecRef, is_app

from halmos.bytevec import ByteVec
from halmos.config import Config, TraceEvent
from halmos.exceptions import HalmosException
from halmos.mapper import DeployAddressMapper, Mapper
from halmos.sevm import (
    CallContext,
    CallSequence,
    EventLog,
    StorageRead,
    StorageWrite,
    mnemonic,
)
from halmos.utils import (
    Address,
    byte_length,
    cyan,
    green,
    hexify,
    is_bv,
    magenta,
    red,
    unbox_int,
    yellow,
)

config_context: ContextVar[Config | None] = ContextVar("config", default=None)


def rendered_initcode(context: CallContext) -> str:
    message = context.message
    data = message.data

    initcode_str = ""
    args_str = ""

    if (
        isinstance(data, BitVecRef)
        and is_app(data)
        and data.decl().kind() == Z3_OP_CONCAT
    ):
        children = [arg for arg in data.children()]
        if isinstance(children[0], BitVecNumRef):
            initcode_str = hex(children[0].as_long())
            args_str = ", ".join(map(str, children[1:]))
    else:
        initcode_str = hexify(data)

    return f"{initcode_str}({cyan(args_str)})"


def render_output(context: CallContext, file=sys.stdout) -> None:
    output = context.output
    returndata_str = "0x"
    failed = output.error is not None

    if not failed and context.is_stuck():
        return

    data = output.data
    if data is not None:
        is_create = context.message.is_create()
        if hasattr(data, "unwrap"):
            data = data.unwrap()

        returndata_str = (
            f"<{byte_length(data)} bytes of code>"
            if (is_create and not failed)
            else hexify(data)
        )

    ret_scheme = context.output.return_scheme
    ret_scheme_str = f"{cyan(mnemonic(ret_scheme))} " if ret_scheme is not None else ""
    error_str = f" (error: {repr(output.error)})" if failed else ""

    color = red if failed else green
    indent = context.depth * "    "
    print(
        f"{indent}{color('↩ ')}{ret_scheme_str}{color(returndata_str)}{color(error_str)}",
        file=file,
    )


def rendered_address(addr: Address, replace_with_contract_name: bool = True) -> str:
    addr = unbox_int(addr)
    addr_str = str(addr) if is_bv(addr) else hex(addr)

    # check if we have a contract name for this address in our deployment mapper
    if replace_with_contract_name:
        addr_str = DeployAddressMapper().get_deployed_contract(addr_str)

    return addr_str


def rendered_log(log: EventLog) -> str:
    opcode_str = f"LOG{len(log.topics)}"
    topics = [
        f"{cyan(f'topic{i}')}={hexify(topic)}" for i, topic in enumerate(log.topics)
    ]
    data_str = f"{cyan('data')}={hexify(log.data)}"
    args_str = ", ".join(topics + [data_str])

    return f"{opcode_str}({args_str})"


def rendered_slot(slot: Address) -> str:
    slot = unbox_int(slot)

    if is_bv(slot):
        return magenta(hexify(slot))

    if slot < 2**16:
        return magenta(str(slot))

    return magenta(hex(slot))


def rendered_sstore(update: StorageWrite) -> str:
    slot_str = rendered_slot(update.slot)
    opcode = cyan("TSTORE" if update.transient else "SSTORE")
    return f"{opcode} @{slot_str} ← {hexify(update.value)}"


def rendered_sload(read: StorageRead) -> str:
    slot_str = rendered_slot(read.slot)
    opcode = cyan("TLOAD" if read.transient else "SLOAD")
    return f"{opcode}  @{slot_str} → {hexify(read.value)}"


def rendered_trace(context: CallContext) -> str:
    with io.StringIO() as output:
        render_trace(context, file=output)
        return output.getvalue()


def rendered_calldata(calldata: ByteVec, contract_name: str | None = None) -> str:
    if not calldata:
        return "0x"

    if len(calldata) < 4:
        return hexify(calldata)

    if len(calldata) == 4:
        return f"{hexify(calldata.unwrap(), contract_name)}()"

    selector = calldata[:4].unwrap()
    args = calldata[4:].unwrap()
    return f"{hexify(selector, contract_name)}({hexify(args)})"


def render_trace(context: CallContext, file=sys.stdout) -> None:
    config: Config = config_context.get()
    if config is None:
        raise HalmosException("config not set")

    message = context.message
    addr_str = rendered_address(message.target)
    caller_str = f" (caller: {rendered_address(message.caller)})"

    value = unbox_int(message.value)
    value_str = f" (value: {value})" if is_bv(value) or value > 0 else ""

    call_scheme_str = f"{cyan(mnemonic(message.call_scheme))} "
    indent = context.depth * "    "

    if message.is_create():
        # TODO: select verbosity level to render full initcode
        # initcode_str = rendered_initcode(context)

        try:
            if context.output.error is None:
                target = hex(int(str(message.target)))
                bytecode = context.output.data.unwrap().hex()
                contract_name = Mapper().get_by_bytecode(bytecode).contract_name

                DeployAddressMapper().add_deployed_contract(target, contract_name)
                addr_str = contract_name
        except Exception:
            # TODO: print in debug mode
            ...

        initcode_str = f"<{byte_length(message.data)} bytes of initcode>"
        print(
            f"{indent}{call_scheme_str}{addr_str}::{initcode_str}{value_str}", file=file
        )

    else:
        calldata = rendered_calldata(message.data, addr_str)
        call_str = f"{addr_str}::{calldata}"
        static_str = yellow(" [static]") if message.is_static else ""
        print(
            f"{indent}{call_scheme_str}{call_str}{static_str}{value_str}{caller_str}",
            file=file,
        )

    log_indent = (context.depth + 1) * "    "
    for trace_element in context.trace:
        match trace_element:
            case CallContext():
                render_trace(trace_element, file=file)
            case EventLog():
                if TraceEvent.LOG in config.trace_events:
                    print(f"{log_indent}{rendered_log(trace_element)}", file=file)
            case StorageRead():
                if TraceEvent.SLOAD in config.trace_events:
                    print(f"{log_indent}{rendered_sload(trace_element)}", file=file)
            case StorageWrite():
                if TraceEvent.SSTORE in config.trace_events:
                    print(f"{log_indent}{rendered_sstore(trace_element)}", file=file)
            case _:
                raise HalmosException(f"unexpected trace element: {trace_element}")

    render_output(context, file=file)

    if context.depth == 1:
        print(file=file, end="")


def render_call_sequence(call_sequence: CallSequence, file=sys.stdout) -> None:
    for call in call_sequence:
        render_trace(call, file=file)


def rendered_call_sequence(call_sequence: CallSequence) -> str:
    with io.StringIO() as output:
        render_call_sequence(call_sequence, file=output)
        return output.getvalue()

import io
import sys

from z3 import Z3_OP_CONCAT, BitVecNumRef, BitVecRef, is_app

from halmos.bytevec import ByteVec
from halmos.exceptions import HalmosException
from halmos.sevm import CallContext, EventLog
from halmos.utils import (
    DeployAddressMapper,
    Mapper,
    byte_length,
    cyan,
    green,
    hexify,
    is_bv,
    mnemonic,
    red,
    unbox_int,
    yellow,
)


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


def rendered_log(log: EventLog) -> str:
    opcode_str = f"LOG{len(log.topics)}"
    topics = [
        f"{cyan(f'topic{i}')}={hexify(topic)}" for i, topic in enumerate(log.topics)
    ]
    data_str = f"{cyan('data')}={hexify(log.data)}"
    args_str = ", ".join(topics + [data_str])

    return f"{opcode_str}({args_str})"


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
    message = context.message
    addr = unbox_int(message.target)
    addr_str = str(addr) if is_bv(addr) else hex(addr)
    # check if we have a contract name for this address in our deployment mapper
    addr_str = DeployAddressMapper().get_deployed_contract(addr_str)

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
        print(f"{indent}{call_scheme_str}{call_str}{static_str}{value_str}", file=file)

    log_indent = (context.depth + 1) * "    "
    for trace_element in context.trace:
        if isinstance(trace_element, CallContext):
            render_trace(trace_element, file=file)
        elif isinstance(trace_element, EventLog):
            print(f"{log_indent}{rendered_log(trace_element)}", file=file)
        else:
            raise HalmosException(f"unexpected trace element: {trace_element}")

    render_output(context, file=file)

    if context.depth == 1:
        print(file=file)

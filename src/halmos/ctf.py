import argparse

from .__main__ import gen_model
from .byte2op import decode
from .sevm import ops_to_pgm, SEVM
from z3 import SolverFor, BitVec, BitVecVal, Extract


def main():
    parser = argparse.ArgumentParser(prog='halmos-ctf', epilog='For more information, see https://github.com/a16z/halmos')
    parser.add_argument('code', help='bytecode to execute')
    parser.add_argument('--solver-timeout-branching', metavar='TIMEOUT', type=int, default=1000, help='set timeout (in milliseconds) for solving branching conditions (default: %(default)s)')
    parser.add_argument('--solver-timeout-assertion', metavar='TIMEOUT', type=int, default=60000, help='set timeout (in milliseconds) for solving assertion violation conditions (default: %(default)s)')
    args = parser.parse_args()

    options = {
        'verbose': 3,
        'debug': True,
        'timeout': args.solver_timeout_branching,
    }

    # bytecode
    (ops, code) = decode(args.code)
    pgm = ops_to_pgm(ops)

    # storage
    storage = {}

    # solver
    solver = SolverFor('QF_AUFBV') # quantifier-free bitvector + array theory; https://smtlib.cs.uiowa.edu/logics.shtml
    solver.set(timeout=args.solver_timeout_branching)

    # caller
    caller = BitVec('msg_sender', 256)
    solver.add(Extract(255, 160, caller) == BitVecVal(0, 96))

    # this
    this = BitVec('this_address', 256)
    solver.add(Extract(255, 160, this) == BitVecVal(0, 96))


    sevm = SEVM(options)
    (exs, _) = sevm.run(
        sevm.mk_exec(
            pgm       = { this: pgm },
            code      = { this: code },
            storage   = { this: storage },
            balance   = { this: BitVec('this_balance', 256) },
            calldata  = [None] * 4,
            callvalue = BitVec('msg_value', 256),
            caller    = caller,
            this      = this,

            #
            solver    = solver,
        )
    )

    models = []
    for idx, ex in enumerate(exs):
        opcode = ex.pgm[ex.this][ex.pc].op[0]

        if opcode == 'STOP' or opcode == 'RETURN':
            gen_model(args, models, idx, ex)
            print(f'Using {models[-1][0]} triggers a successful execution path 🥳')


if __name__ == '__main__':
    main()

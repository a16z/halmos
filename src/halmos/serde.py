import json

from typing import *
from z3 import Solver, deserialize as z3_deserialize, BitVecRef, ExprRef, SolverFor


def save_json(exec_obj: Any, filename: str) -> None:
    with open(filename, 'w') as f:
        json.dump(exec_obj, f)

def load_json(filename: str) -> Any:
    with open(filename, 'r') as f:
        return json.load(f)

def serialize(item: Any) -> Any:
    if item is None:
        return None

    # XXX: just to avoid verbose warnings
    if isinstance(item, (str, int, bool)):
        return item

    if isinstance(item, bytes):
        return '0x' + item.hex()

    if isinstance(item, dict):
        return { serialize(k): serialize(v) for k, v in item.items() }

    if isinstance(item, list):
        return [ serialize(x) for x in item ]

    if isinstance(item, tuple):
        return tuple(serialize(x) for x in item)

    if isinstance(item, Solver):
        return item.to_smt2()

    # covers z3.BitVecRef, z3.ArrayRef, sevm.Contract, ...
    if hasattr(item, 'serialize'):
        return item.serialize()

    if hasattr(item, '__dict__'):
        # print(f'Warning: serializing {item} with type {type(item)} as dict')
        return serialize(item.__dict__)

    print(f'Warning: item with type {type(item)} returned as-is')
    return item


def fancy_type(t: Any) -> str:
    if isinstance(t, dict):
        for k, v in t.items():
            return f'dict({fancy_type(k)}, {fancy_type(v)}'

    if isinstance(t, list):
        if len(t) == 0:
            return 'list(?)'
        else:
            return f'list({fancy_type(t[0])})'

    return str(type(t))


Address = BitVecRef # 160-bitvector

def new_solver_from_string(cls, value: str) -> Solver:
    s = SolverFor('QF_AUFBV')
    s.from_string(value)
    return s

def z3__pydantic__deserialize():
    yield z3_deserialize

def z3__pydantic__from_string():
    yield new_solver_from_string

# this tells pydantic to use the __get_validators function to parse/validate BitVecRef
BitVecRef.__get_validators__ = z3__pydantic__deserialize
ExprRef.__get_validators__ = z3__pydantic__deserialize
Solver.__get_validators__ = z3__pydantic__from_string

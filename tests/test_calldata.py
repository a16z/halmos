from halmos.calldata import BaseType, DynamicArrayType, DynamicParams
from halmos.cheatcodes import permutate_dyn_size
from halmos.utils import extract_bytes, int_of

# auto-generated by cursor


# Mock classes and functions
class MockSEVM:
    class Options:
        pass

    options = Options()


class MockExecutor:
    def new_symbol_id(self):
        return 0


class MockFunctionInfo:
    def __init__(self):
        self.name = "testFunction"
        self.sig = "testFunction(uint256[],string)"
        self.selector = "0x12345678"


def extract_size_argument(calldata, arg_idx) -> int:
    offset = int_of(
        extract_bytes(calldata, 4 + arg_idx * 32, 32),
        "symbolic offset for bytes argument",
    )
    length = int_of(
        extract_bytes(calldata, 4 + offset, 32),
        "symbolic size for bytes argument",
    )
    return length


def test_permutate_dyn_size():
    # Setup
    dyn_param_size = DynamicParams()
    dyn_param_size.append(
        "param1", 2, DynamicArrayType("param1", BaseType("", "uint256"))
    )
    dyn_param_size.append("param2", 32, BaseType("param2", "string"))

    funselector = "0x12345678"
    abi = [
        {
            "name": "testFunction",
            "type": "function",
            "inputs": [
                {"name": "param1", "type": "uint256[]"},
                {"name": "param2", "type": "string"},
            ],
        }
    ]
    funinfo = MockFunctionInfo()
    sevm = MockSEVM()
    ex = MockExecutor()

    # Call the function
    result = permutate_dyn_size(dyn_param_size, funselector, abi, funinfo, sevm, ex)

    # Assertions
    assert len(result) == 12  # 3 options for param1 * 4 options for param2

    # Check that all expected sizes are present
    expected_sizes = {"param1": [0, 1, 2], "param2": [0, 32, 65, 1024]}

    for calldata in result:
        param1_size = extract_size_argument(calldata, 0)
        param2_size = extract_size_argument(calldata, 1)

        assert param1_size in expected_sizes["param1"]
        assert param2_size in expected_sizes["param2"]

    # Check that all combinations are present
    combinations = set(
        (extract_size_argument(c, 0), extract_size_argument(c, 1)) for c in result
    )
    assert len(combinations) == 12

    # Check the structure of the calldata
    for calldata in result:
        assert calldata[:4].unwrap() == b"\x12\x34\x56\x78"  # function selector
        assert len(calldata) >= 132  # minimum length for two dynamic parameters

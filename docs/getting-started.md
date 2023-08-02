# How to write symbolic tests with Halmos

Symbolic tests looks similar to fuzz tests, but there are certain differences that need to be understood. This guide will walk you through the process of writing symbolic tests, highlighting the differences compared to fuzz tests. It is intended for those who are already familiar with [Dapptools]-/[Foundry]-style fuzz tests. If you haven't experienced fuzz tests before, please refer to the [Foundry document][Foundry Fuzz Testing] to grasp the basic concepts.

[Dapptools]: <https://dapp.tools/>
[Foundry]: <https://book.getfoundry.sh/>
[Foundry Fuzz Testing]: <https://book.getfoundry.sh/forge/fuzz-testing>

## 0. Install Halmos

Halmos is available as a [Python package][Halmos Package], and can be installed using `pip`:
```
pip install halmos
```

[Halmos Package]: <https://pypi.org/project/halmos/>

**Tips:**

- If you want to try out the nightly build version, you can install it from the Github repository:
  ```
  pip install git+https://github.com/a16z/halmos
  ```

- If you're not familiar with managing Python packages, we recommend using `venv`. Create a virtual environment and install Halmos within it:
  ```
  python3 -m venv <venv-dir>
  source <venv-dir>/bin/activate
  pip install halmos
  ```
  You can activate or deactivate the virtual environment before or after using Halmos:
  ```
  # to activate:
  source <venv-dir>/bin/activate

  # to deactivate:
  deactivate
  ```

## 1. Write setUp()

Similar to foundry tests, you can provide the `setUp()` function that will be executed before each test. In the setup function, you can create an instance of the target contracts, and initialize their state. These initialized contracts will then be accessible for every test.

Furthermore, you are also allowed to call the constructor with symbolic arguments, initializing the contract state to be symbolic. You can create those symbols using [Halmos cheatcodes].

[Halmos cheatcodes]: <https://github.com/a16z/halmos-cheatcodes>

For example, consider a basic ERC20 token contract as shown below:
```solidity
import {ERC20} from "openzeppelin/token/ERC20/ERC20.sol";

contract MyToken is ERC20 {
    constructor(uint256 initialSupply) ERC20("MyToken", "MT") {
        _mint(msg.sender, initialSupply);
    }
}
```
Then you can write a `setUp()` function that creates a new token contract with a _symbolic_ initial supply, as follows:
```solidity
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract MyTokenTest is SymTest {
    MyToken token;

    function setUp() public {
        uint256 initialSupply = svm.createUint256('initialSupply');
        token = new MyToken(initialSupply);
    }
}
```
In the above example, `svm.createUint256()` is a symbolic cheatcode that generates a new symbol of type `uint256`. It's important to understand that the created symbol represents a _set_ of all integers within the range of `[0, 2^256 - 1]`, rather than being a random value selected from the range. <!--Refer to [the symbolic execution document](symbolic-execution.md) to learn more about the concept of symbols.-->

By using the symbolic initial supply, you can check if the given tests pass for all possible initial supply configurations, rather than just a randomly selected supply setup.

**Tips:**

- The Halmos cheatcodes can be installed like any other Solidity dependencies:
  ```
  forge install a16z/halmos-cheatcodes
  ```

- The current list of available Halmos cheatcodes can be found [here][halmos-cheatcodes-list].

[halmos-cheatcodes-list]: <https://github.com/a16z/halmos-cheatcodes/blob/main/src/SVM.sol>

## 2. Write symbolic tests

Symbolic tests are structured similarly to fuzz tests. In most cases, they follow the pattern outlined below:
```
function check_<function-name>_<behavior-description> ( <parameters> ) {
    // specify input conditions
    ...

    // call target contracts
    ...

    // check output states
    ...
}
```

Below is an example symbolic test for the token transfer function:
```solidity
function check_transfer(address sender, address receiver, uint256 amount) public {
    // specify input conditions
    vm.assume(receiver != address(0));
    vm.assume(token.balance(sender) >= amount);

    // record the current balance of sender and receiver
    uint256 balanceOfSender = token.balanceOf(sender);
    uint256 balanceOfReceiver = token.balanceOf(receiver);

    // call target contract
    vm.prank(sender);
    token.transfer(receiver, amount);

    // check output state
    assert(token.balanceOf(sender) == balanceOfSender - amount);
    assert(token.balanceOf(receiver) == balanceOfReceiver + amount);
}
```

We will explain each component using the above test as a running example.

### 2.1 Declare or create symbolic inputs

Similar to fuzz tests, you can specify input parameters for each test.

For instance, our example test declares three input parameters: `sender`, `receiver`, and `amount`, as follows:
```solidity
function check_transfer(address sender, address receiver, uint256 amount) ...
```

Unlike fuzz tests, however, in symbolic tests, each input parameter is assigned a symbol that represents all possible values of the given type. In our example, `sender` and `receiver` are assigned an address symbol that ranges from `0x0` to `0xffff...ffff`, and `amount` is assigned an integer symbol ranging over `[0, 2^256-1]`.

Conceptually, each symbolic test represents a large number of test cases generated by replacing the symbols with every possible input combination. In other words, it's analogous to running an extensive loop as follows:[^symbolic-execution]
```solidity
// conceptual effect of symbolic testing of `check_transfer()`
for (uint160 sender = 0; sender < type(uint160).max; sender++) {
    for (uint160 receiver = 0; receiver < type(uint160).max; receiver++) {
        for (uint256 amount = 0; amount < type(uint256).max; amount++) {
            check_transfer(address(sender), address(receiver), amount);
        }
    }
}
```

[^symbolic-execution]: Note that the number of possible input combinations in our example is `2^160 * 2^160 * 2^256`, and it is computationally infeasible to actually run all of them individually. As a solution, symbolic testing employs the symbolic execution technique, which enables testing all the input combinations without actually running them individually.

**Tips:**

- Instead of declaring symbolic input parameters, you can dynamically create symbols inside the test using the Halmos cheatcodes. For instance, our running example can be rewritten as follows:
  ```solidity
  function check_transfer() {
      address sender = svm.createAddress("sender");
      address receiver = svm.createAddress("receiver");
      uint256 amount = svm.createUint256("amount");
      ...
  }
  ```

- Halmos requires dynamically-sized arrays (including `bytes` and `string`) to be given with a fixed size. Thus they cannot be declared as input parameters, but need to be programmatically constructed. For example, a byte array can be generated using the `svm.createBytes()` cheatcode as follows:
  ```solidity
  bytes memory data = svm.createBytes(96, 'data');
  ```
  Similarly, a dynamic array of integers can be created as shown below:
  ```solidity
  uint256[] memory arr = new uint256[3];
  for (uint i = 0; i < 3; i++) {
      arr[i] = svm.createUint256('element');
  }
  ```
  We are planning to implement more cheatcodes and features that can make it easier to declare or create dynamic arrays.

### 2.2 Specify input conditions

Recall that symbolic tests take into account all possible input combinations. However, not all input combinations are relevant or valid for every test scenario. Similar to fuzz tests, you can use `vm.assume()` to specify the conditions for valid inputs.

In our example, the conditions for the valid sender and receiver addresses are specified as follows:
```solidity
vm.assume(receiver != address(0));
vm.assume(token.balance(sender) >= amount);
```
Like fuzz tests, any input combinations that don't satisfy the `assume()` conditions are disregarded. This means that, after executing the above `assume()` statements, only the input combinations in which the receiver is non-zero and the sender has sufficient balance are considered. Other input combinations that violate these conditions are ignored.

**Tips:**

- You need to be careful not to exclude valid inputs by setting too strong input conditions.

- In symbolic tests, avoid using `bound()` as it tends to perform poorly. Instead, use `vm.assume()` which is more efficient and enhances readability:
  ```solidity
  uint256 tokenId = svm.createUint256("tokenId");

  // ❌ don't do this
  tokenId = bound(tokenId, 1, MAX_TOKEN_ID);

  // ✅ do this
  vm.assume(1 <= tokenId && tokenId <= MAX_TOKEN_ID);
  ```

### 2.3 Call target contracts

Now you can invoke the target contracts with the prepared input symbols.

In our example, the transfer function is called with the symbolic receiver address and amount. The `prank()` cheatcode is also used to set `msg.sender` to the symbolic sender address, as shown below:
```solidity
vm.prank(sender);
token.transfer(receiver, amount);
```

**Tips:**

- If your goal is to check whether the target contract reverts under the expected conditions, a low-level call should be used. This allows the execution to continue even if the external call fails. Below is an example of a low-level call to the token transfer function. Note that the return value `success` can be subsequently used to check the reverting conditions.
  ```solidity
  vm.prank(sender);
  (bool success,) = address(token).call(
      abi.encodeWithSelector(token.transfer.selector, receiver, amount)
  );
  if (!success) {
      // check conditions for transfer failure
  }
  ```

### 2.4 Check output states

After calling the target contracts, you can write assertions against the output state of the contracts.

In our example, the following assertions against the output state of the token contract are provided:
```solidity
assert(token.balanceOf(sender) == balanceOfSender - amount);
assert(token.balanceOf(receiver) == balanceOfReceiver + amount);
```

If there are any inputs that violate these assertions, Halmos will reports those inputs, referred to as counterexamples.

For our example, Halmos will identify an input combination where the sender address is identical to the receiver address. This is because self-transfers do not alter the balance, leading to scenarios where the above assertions are not satisfied.

**Tips:**

- Halmos focuses solely on assertion violations (i.e., revert with `Panic(1)`), disregarding other revert cases. This means that Halmos doesn't report any inputs that lead to other types of revert. For instance, in our example, any inputs that trigger an overflow in `balanceOfReceiver + amount`, or inputs causing the external contract call to fail will be ignored. To avoid disregarding such inputs, you can utilize an `unchecked` block or a low-level call.

- If you're using an older compiler version (`< 0.8.0`) that uses the `INVALID` opcode for assertion violation, rather than the `Panic(1)` error code, then Halmos will _not_ report any counterexamples. In that case, you will need to use a custom assertion that reverts with `Panic(1)` upon failure, as shown below:
  ```solidity
  function myAssert(bool cond) internal pure {
      if (!cond) {
          assembly {
              mstore(0x00, 0x4e487b71) // Panic()
              mstore(0x20, 0x01)       // 1
              revert(0x1c, 0x24)       // revert Panic(1)
          }
      }
  }
  ```

## Summary

Similar to fuzz tests, symbolic tests are structured as follows:
- Declaration of test input parameters.
- Specification of conditions for valid inputs.
- Invocation of the target contracts.
- Assertions regarding the expected output states.

However, since symbolic tests are performed symbolically, certain behavioral differences need to be considered:
- Test inputs are assigned symbolics, rather than random values.
- Only assertion violations, that is, `Panic(1)` errors, are reported, whereas other errors such as arithmetic overflows are disregarded.
- The `vm.assume()` cheatcode performs better than `bound()`.

For further insights, refer to [examples of symbolic tests](../examples/README.md).

Join the [Halmos Telegram Group] for any inquiries or further discussions.

[Halmos Telegram Group]: <https://t.me/+4UhzHduai3MzZmUx>

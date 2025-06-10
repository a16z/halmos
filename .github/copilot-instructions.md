# Project Context

Halmos is a symbolic execution tool for Ethereum Virtual Machine (EVM) bytecode, with a focus on simplicity, performance and usability. It leverages foundry-style tests written in Solidity to let developers specify how to set up their test environment and what properties to check.

It interfaces with Satisfyability Modulo Theories (SMT) solvers like z3 to find bugs or rule them out.

## Development Flow

```shell
# run the linter
ruff check src/

# run the formatter
ruff format src/

# run unit tests only (2-3s)
uv run pytest -vv -k "not long and not ffi and not regression"

# run regression/e2e tests (2-3m)
uv run pytest -vv -k "not long and not ffi"
```

## Python Coding Conventions

### Use Python ≥ 3.11

Use modern language features when they improve clarity or safety, but ensure every file runs on 3.11, the oldest supported target.

### Avoid Introducing New Dependencies

Do not add external packages or frameworks unless the benefit is clear and measurable. A tiny helper function can be written or vendored instead of pulling in an entire library.

### Use Meaningful Names

Choose descriptive variable, function, and class names. Short names like `i`, `j`, or `n` are fine for loop counters or sizes when context is obvious.

### Follow PEP 8

Stick to the PEP 8 style guide and let `ruff` enforce it automatically—no bikeshedding.

### Use Docstrings

Document every public function, method, and class with a docstring that explains purpose, parameters, return values, and raised exceptions.

### Keep It Simple

Favor straightforward solutions over clever ones. Functions longer than \~50 lines probably need refactoring into smaller, testable units.

### Use List Comprehensions

Prefer list (or set / dict) comprehensions over manual loops when they keep the code readable.

### Handle Exceptions

Wrap risky operations in `try .. except` blocks and handle errors gracefully, catching only the specific exceptions you expect. Avoid naked excepts (`except` without a type) and swallowing exceptions (`except` block with just a `pass`).

### Use Virtual Environments

Isolate project dependencies with a virtual environment. Never install dependencies in the global environment.

### Write Tests

Provide unit tests (pytest recommended) for new features and regressions to keep the codebase reliable.

### Use Type Hints

Annotate code with modern type syntax.

Prefer `A | B` to `typing.Union[A, B]`.

Prefer `A | None` to `typing.Optional[A]`.

Reserve `typing.Any` for unavoidable cases.

### Avoid Global Variables

Minimize globals to reduce side effects. Module-level singletons are acceptable when justified.

### Use Dataclasses, Preferably Immutable

Leverage `@dataclass(frozen=True, slots=True)` for lightweight, well-typed value objects.

### Avoid Raw Dicts and Tuples

Use plain `dict` only for truly dynamic key sets; otherwise, model data with dataclasses.

Pass tuples only for simple, positional return values.

### Use Algebraic Data Types

Model variant data with union types (`|`) and `match` statements rather than deep inheritance trees. Always handle the default case.

### Use Context Managers

Employ `with` statements (or custom `__enter__` / `__exit__`) to manage resources like files, sockets, or locks automatically.

### Use Early Exits

Reduce nesting by validating inputs up front and returning early (or using `continue` inside long loops) when appropriate.

### Outside of Early Exits, Avoid Multiple Returns

Deeply nested or scattered `return` statements make control flow hard to follow—limit them to guard clauses at the top.

### Avoid Low Information Comments

Don't write comments that merely restate what the code does (like `i += 1 # increment i`) or rephrase function names. Instead focus on the "why".

### Don't Use Monkey-Patching

Adding attributes or overriding functions at runtime is just bad form.



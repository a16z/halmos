# solvers package

A minimalist Docker image containing high-performance SMT solvers.

## Quick start

```sh
# Step 1: Pull the image
docker pull ghcr.io/a16z/solvers:latest

# Step 2: Tag the image with a shorter name
docker tag ghcr.io/a16z/solvers:latest solvers

# Step 3: Run the container using the shorter name,
for solver in bitwuzla boolector cvc5 stp yices z3 ; do \
    echo --- $solver && \
    docker run --rm solvers $solver --version ; \
done

# Step 4: create an example smt2 file:
cat << EOF > checkSanity.smt2
(set-logic QF_BV)
(assert (= (bvsdiv (_ bv3 2) (_ bv2 2)) (_ bv0 2)))
(check-sat)
(exit)
EOF

# Step 5: invoke each solver on the file
# (`-v .:/workspace` mounts the current working directory under /workspace on the container, making the files available there)
for solver in bitwuzla boolector cvc5 stp yices-smt2 z3 ; do \
    echo -n "$solver: " && \
    docker run --rm -v .:/workspace solvers $solver checkSanity.smt2 ; \
done
```

## Available solvers

```
bitwuzla: 0.6.0-dev-main@5b2d83f
boolector: 3.2.4
cvc5: 1.1.2
stp: 2.3.3
yices: 2.6.4
z3: 4.13.3
```

## Contributing

Everyone is welcome to contribute new solvers or new versions to the image via pull requests. If a solver is competitive at [SMT-COMP](https://smt-comp.github.io), it would be great to have it included in the image.

When possible, we prefer release binaries from an official source like the Github releases for the project to minimize the time it takes to build the image. If you're unsure about a particular solver or how to integrate it, consider reaching out on the [Halmos Dev Chat](https://t.me/+4UhzHduai3MzZmUx).

Before opening the pull request, please test your changes by verifying:

* that you can build the image locally
* that you can correctly invoke the solver as described in the [Quick Start](https://github.com/a16z/halmos/tree/main/packages/solvers#quick-start) section
* update this README with the name, version and source of the solver

Thank you in advance!


## Credit

Based on [EmperorOrokuSaki/solvers](https://github.com/EmperorOrokuSaki/solvers)

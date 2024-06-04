# solvers package

## Usage

Checking versions:

```sh
for solver in bitwuzla boolector cvc5 stp yices z3 ; do \
    echo --- $solver && \
    docker run --rm ghcr.io/a16z/solvers:latest $solver --version ; \
done
```

## Solvers

| Solver | Version | URL | Notes
| ------ | ------- | --- | ----- |
| Bitwuzla | 0.5.0-dev-main@50ce452 | [bitwuzla/bitwuzla](https://github.com/bitwuzla/bitwuzla) | Built from source
| Boolector | 3.2.3 | [boolector/boolector](https://github.com/boolector/boolector) | Built from source
| CVC5 | 1.1.2 | [cvc5/cvc5](https://github.com/cvc5/cvc5) | Installed from Github release binaries
| STP | 2.3.3 | [stp/stp](https://github.com/stp/stp) | Provides a great Dockerfile that shows how to do a static build. We just copy the binary from the `msoos/stp` image since releases aren't too frequent. |
| Yices | 2.6.4 | [SRI-CSL/yices2](https://github.com/SRI-CSL/yices2) | Installed from Github release binaries
| Z3 | 4.13.1 | [Z3Prover/z3](https://github.com/Z3Prover/z3) | Includes a [Dockerfile](https://github.com/Z3Prover/z3/blob/master/docker/ubuntu-20-04.Dockerfile) and a package but no `latest` tag |



## Credit

Based on [EmperorOrokuSaki/solvers](https://github.com/EmperorOrokuSaki/solvers)

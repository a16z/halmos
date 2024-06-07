# halmos Docker image

```sh
# build it
docker build -t halmos --file packages/halmos/Dockerfile .

# run it
docker run --rm -v .:/workspace halmos --root tests/regression --function check_log_string

# run the container interactively (for debugging)
docker run --rm -v .:/workspace -it --entrypoint bash halmos

# run tests
docker run -v .:/workspace --entrypoint pytest halmos -k test_config.py
```

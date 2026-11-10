# dolmos Docker image

```sh
# build it
docker build -t dolmos --file packages/dolmos/Dockerfile .

# run it
docker run --rm -v .:/workspace dolmos --root tests/regression --function check_log_string

# run the container interactively (for debugging)
docker run --rm -v .:/workspace -it --entrypoint bash dolmos

# run tests
docker run -v .:/workspace --entrypoint pytest dolmos -k test_config.py
```

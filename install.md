# Installation

## 1. Python

The Status Validator was tested with

- Python 3.12+

If you don't have it installed, please download it from <https://www.python.org/downloads/> and follow the [Python Developer's Guide](https://devguide.python.org/getting-started/).

## 2. How to run the Status Validator?

1. Clone the repository
    
    `git clone git@github.com:eu-digital-identity-wallet/eudi-srv-status-validator-py.git`

2. Create a `.venv` folder within the cloned repository:

    ```shell
    cd eudi-srv-status-validator-py
    python3 -m venv .venv
    ```

3. Activate the environment:

   Linux/macOS

    ```shell
    . .venv/bin/activate
    ```

    Windows

    ```shell
    . .venv\Scripts\Activate
    ```
    
4. Install or upgrade _pip_

    ```shell
    python -m pip install --upgrade pip
    ```
    
5. Install Flask and the other dependencies in the virtual environment

    ```shell
    pip install -r requirements.txt
    ```

6. Update `config.yaml`

    Update `trust_validator.url` to point at your trust validator instance.
    To use another file, set `CONFIG_PATH` to its path.

7. Start with Flask

    ```bash
    FLASK_APP="app:create_app()" flask run
    ```

    The service listens on `http://127.0.0.1:5000` by default (`--host` and `--port` change it).

## 3. Run with Docker

The image `ghcr.io/eu-digital-identity-wallet/eudi-srv-status-validator-py` is built by `.github/workflows/pipeline.yml`
(`:latest` from `main`, `:branch-<name>` from each `branch-*`, `:<version>` from `v*` tags). To build it locally:

```shell
docker build -t eudi-srv-status-validator-py .
```

The image contains the repository's `config.yaml` as its default configuration. `docker-compose.yml` runs it on
host port 5004 with `CONFIG_PATH=/etc/status_validator_config/config.yaml`: write your configuration there
(at least `trust_validator.url`) before `docker compose up -d`. The container runs as UID 10001 and writes nothing
to disk; the Status List cache is in memory, per container.

## 4. Run the tests

```shell
pip install -r requirements-dev.txt
pytest --cov=app --cov-config=pyproject.toml
```

The tests need no network access: the issuer and the trust validator are replaced by fakes, and the Status List
Tokens are signed with throw-away keys.

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
    
5. Install Flask, gunicorn and other dependencies in virtual environment

    ```shell
    pip install -r requirements.txt
    ```

6. Update `config.yaml`

    Update `trust_validator.url` to point at your trust validator instance.

7. Start with Flask

    ```bash
    FLASK_APP="app:create_app()" flask run
    ```

    The service listens on `http://0.0.0.0:5000` by default.

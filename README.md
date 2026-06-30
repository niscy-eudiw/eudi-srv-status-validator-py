# eudi-srv-status-validator-py

Flask service that checks the validity of one or more Referenced Tokens against a **Token Status List**, following [draft-ietf-oauth-status-list-10](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/10/).

Given an index (`idx`), a status list URI (`uri`), and a `validation_context`, the service:
1. Fetches the Status List Token JWT from the issuer URI.
2. Extracts the `x5c` certificate chain from the JWT header.
3. Validates the chain via an external trust validator API, scoped by the supplied `validation_context`.
4. Verifies the JWT signature using the leaf certificate's public key.
5. Decompresses the `lst` field and reads the bit at position `idx`.
6. Returns whether the token is valid or invalid (revoked).
7. Caches the verified Status List in memory (TTL driven by the JWT's `ttl`/`exp` claims).

Multiple checks can also be submitted in a single request via a `checks` array (batch mode, capped at 100 items (default)), with each item processed independently and returned with its own per-item result.

---

## Requirements

- Python 3.12+
---

## Configuration

All settings live in `config.yaml`. 

---

## Running natively

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Edit `config.yaml`

Set `trust_validator.url` to point at your trust validator instance.

### 3. Start with Flask

```bash
FLASK_APP="app:create_app()" flask run
```

The service listens on `http://0.0.0.0:5000` by default.

---

## API Documentation

The full API specification, including request/response schemas and interactive testing, is available via Swagger UI.

* **Swagger UI:** Go to `/swagger-ui` on your running instance (e.g., `http://localhost:5000/swagger-ui`)
* **OpenAPI Spec:** The raw specification can be fetched directly from `/static/swagger.json`


## :heavy_exclamation_mark: Disclaimer

The released software is a initial development release version:

-   The initial development release is an early endeavor reflecting the efforts of a short timeboxed
    period, and by no means can be considered as the final product.
-   The initial development release may be changed substantially over time, might introduce new
    features but also may change or remove existing ones, potentially breaking compatibility with your
    existing code.
-   The initial development release is limited in functional scope.
-   The initial development release may contain errors or design flaws and other problems that could
    cause system or other failures and data loss.
-   The initial development release has reduced security, privacy, availability, and reliability
    standards relative to future releases. This could make the software slower, less reliable, or more
    vulnerable to attacks than mature software.
-   The initial development release is not yet comprehensively documented.
-   Users of the software must perform sufficient engineering and additional testing in order to
    properly evaluate their application and determine whether any of the open-sourced components is
    suitable for use in that application.
-   We strongly recommend not putting this version of the software into production use.
-   Only the latest version of the software will be supported

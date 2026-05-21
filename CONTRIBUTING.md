# Contributing

Thanks for considering a contribution. This is a small repository; the bar is high for added scope, low for fixes and clarifications.

## Development loop

```powershell
# One-time
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

# Each change
ruff check .
ruff format --check .
mypy function_app.py
pytest -q
```

All four must pass before opening a pull request. CI runs the same set.

## Running the function host locally

See [Local development](README.md#local-development) in the main README. Briefly: install Azure Functions Core Tools and Azurite, then `azurite ...` in one shell and `func start` in another.

## Style

- **No unrequested abstractions.** Three similar lines is better than a premature helper.
- **No comments explaining what the code does.** Reserve comments for non-obvious *why* — a hidden constraint, a subtle invariant.
- **Strict typing.** `mypy --strict` is enforced. Prefer `Final`, `frozenset`, and `typing` over loose annotations.
- **Tests live in `tests/`.** New behaviour requires a test. Mock outbound HTTP — never hit NVD from a test.

## Commit messages

Conventional commits are encouraged but not enforced. Keep the subject under 70 characters; explain *why* in the body.

## Scope discipline

This repository is deliberately small. Features that broaden its remit (new upstream APIs, alternate transports, deployment automation beyond what is already documented) should be discussed in an issue first.

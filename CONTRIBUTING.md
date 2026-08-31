# Contributing

## Local setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a PR

```bash
ruff check tool.py tests
bandit -q -r tool.py -c pyproject.toml
pytest -q
python tool.py --help >/dev/null   # quick smoke test
```

CI runs the same steps on Python 3.10, 3.12, and 3.13.

## Ground rules for this project

- **Stay defensive.** New commands may do recon, passive intel, web hygiene,
  blue-team triage, reporting, or operator productivity. No exploitation,
  auth bypass, phishing, brute force, C2, persistence, or evasion.
- **Never use `shell=True` or `os.system`.** Build a `list[str]` and pass it to
  `run_external()` / `subprocess.run()`.
- **Validate every externally supplied target** through `validate_host()` or
  `normalize_url()` before it reaches a wrapped tool.
- **Active checks must gate on `--yes-i-am-authorized`.**
- Add a test in `tests/` for any new pure function, and an abuse-case test for
  any new input parser.
- If you add a user-facing command group, add a matching `learn` topic in
  `LEARN_TOPICS` so students get context.

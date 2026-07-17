# Contributing

We welcome contributions to the Windows Privilege Escalation Assistant!

## Coding Standards

- The codebase is structured using standard Python modules.
- Ensure that you format code properly (PEP 8 is generally followed).
- Use clear and descriptive names for all classes and functions.
- Every new check plugin must be registered via `@register_check`.

## Adding a New Check

If you find a new vector you want to enumerate, follow these guidelines:

1. Look in `src/privesc_assistant_win/checks/windows/` and create a new file or add to an existing related file.
2. Ensure you inherit from `BaseCheck` (`from privesc_assistant_win.checks.base import BaseCheck`).
3. Return a list of `Finding` objects.
4. **Important**: Add your module to `src/privesc_assistant_win/checks/__init__.py` to ensure it is automatically discovered by the CLI engine.
5. Create a corresponding unit test file in `tests/unit/`.

## Testing

Run tests locally using `pytest`:

```powershell
pip install -e .
pytest tests/
```

Make sure all tests pass before submitting a pull request. Mock Windows-specific APIs where possible so the tests can run on standard CI platforms without error.

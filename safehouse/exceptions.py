"""
safehouse/exceptions.py — kernel-layer exception types.

Defined here (not in safehouse_cli/) so driver.py can re-raise them
without importing from the CLI layer.
"""


class ConfirmationRequired(RuntimeError):
    """Raised when a headless run reaches a step requiring human input."""

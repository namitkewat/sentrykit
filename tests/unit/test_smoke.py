"""Smoke tests that pass on the bare scaffold and keep passing as the core lands."""

from __future__ import annotations

import pytest


@pytest.mark.unit
def test_package_imports_and_reports_version() -> None:
    import sentrykit

    assert sentrykit.__version__


@pytest.mark.unit
def test_error_hierarchy_is_exported_and_consistent() -> None:
    import sentrykit
    from sentrykit.errors import SentrykitError

    for name in (
        "AuthzDenied",
        "NoContext",
        "ArgumentRejected",
        "NoValidArguments",
        "DefaultUnavailable",
        "ValidationFailed",
        "ConfigurationError",
    ):
        err = getattr(sentrykit, name)
        assert issubclass(err, SentrykitError)

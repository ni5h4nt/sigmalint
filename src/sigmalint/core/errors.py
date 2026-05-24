"""Custom exception hierarchy for sigmalint."""

from __future__ import annotations


class SigmalintError(Exception):
    """Base class for all sigmalint-raised errors."""


class ConfigError(SigmalintError):
    """Invalid configuration: bad profile, unknown rule id, malformed YAML."""


class DataLoadError(SigmalintError):
    """Reference data (STIX, schema, taxonomy) could not be loaded."""


class RuleCheckError(SigmalintError):
    """A Rule.check() implementation raised an exception."""

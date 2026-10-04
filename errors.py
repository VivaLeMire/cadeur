from __future__ import annotations


class CadeurError(Exception):
    """Base CADEUR application error with a stable exit code."""

    exit_code = 4


class ConfigurationError(CadeurError):
    exit_code = 2


class TargetError(CadeurError, ValueError):
    exit_code = 3


class ScanRuntimeError(CadeurError):
    exit_code = 4

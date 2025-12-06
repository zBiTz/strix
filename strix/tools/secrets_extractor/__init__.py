"""Extract and detect secrets from files, git history, and Docker configurations."""

from .secrets_extractor import secrets_extractor


__all__ = ["secrets_extractor"]

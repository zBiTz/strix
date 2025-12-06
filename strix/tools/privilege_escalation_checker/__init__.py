"""Check for privilege escalation vectors on Linux and Windows systems."""

from .privilege_escalation_checker import privilege_escalation_checker


__all__ = ["privilege_escalation_checker"]

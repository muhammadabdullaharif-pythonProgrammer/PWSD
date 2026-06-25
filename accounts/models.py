"""Custom user model with role-based access control (RBAC)."""
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Extends Django's AbstractUser with a `role` field for RBAC."""

    class Role(models.TextChoices):
        ADMIN = "ADMIN", "Administrator"
        ANALYST = "ANALYST", "Security Analyst"
        STANDARD = "STANDARD", "Standard User"

    role = models.CharField(
        max_length=16,
        choices=Role.choices,
        default=Role.STANDARD,
        help_text="Determines dashboard capabilities and access scope.",
    )
    organisation = models.CharField(max_length=120, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # convenience predicates ------------------------------------------------
    @property
    def is_admin_role(self) -> bool:
        return self.role == self.Role.ADMIN

    @property
    def is_analyst_role(self) -> bool:
        return self.role == self.Role.ANALYST

    def __str__(self) -> str:
        return f"{self.username} <{self.get_role_display()}>"

"""Auth forms with custom signup including role selection."""
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import User


class SignupForm(UserCreationForm):
    email = forms.EmailField(required=True)
    organisation = forms.CharField(required=False, max_length=120)
    role = forms.ChoiceField(
        choices=[(User.Role.STANDARD, "Standard User"),
                 (User.Role.ANALYST, "Security Analyst")],
        initial=User.Role.STANDARD,
    )

    class Meta:
        model = User
        fields = ("username", "email", "organisation", "role",
                  "password1", "password2")


class LoginForm(AuthenticationForm):
    pass

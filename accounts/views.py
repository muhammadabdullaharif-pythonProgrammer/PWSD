"""Authentication views: signup, login, logout, role-based redirect."""
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods

from .forms import SignupForm, LoginForm
from .models import User


def _role_redirect(user: User) -> str:
    if user.is_admin_role:
        return "/scanner/dashboard/?view=admin"
    if user.is_analyst_role:
        return "/scanner/dashboard/?view=analyst"
    return "/scanner/dashboard/"


@require_http_methods(["GET", "POST"])
def signup_view(request):
    if request.user.is_authenticated:
        return redirect(_role_redirect(request.user))
    form = SignupForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        login(request, user)
        messages.success(request, "Account created successfully.")
        return redirect(_role_redirect(user))
    return render(request, "accounts/signup.html", {"form": form})


@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.user.is_authenticated:
        return redirect(_role_redirect(request.user))
    form = LoginForm(request, data=request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.get_user()
        login(request, user)
        messages.success(request, f"Welcome back, {user.username}.")
        return redirect(_role_redirect(user))
    return render(request, "accounts/login.html", {"form": form})


@login_required
def logout_view(request):
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect("accounts:login")

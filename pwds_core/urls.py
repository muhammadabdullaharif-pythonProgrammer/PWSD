"""Global URL configuration for PWDS."""
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("accounts.urls")),
    path("scanner/", include("scanner.urls")),
    path("chatbot/", include("chatbot.urls")),
    path("", RedirectView.as_view(url="/scanner/dashboard/", permanent=False)),
]

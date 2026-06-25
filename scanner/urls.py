from django.urls import path
from . import views

app_name = "scanner"

urlpatterns = [
    path("dashboard/",          views.dashboard,    name="dashboard"),
    path("history/",            views.history,      name="history"),
    path("scan/<int:pk>/",      views.scan_detail,  name="scan_detail"),
    path("scan/<int:pk>/pdf/",  views.scan_pdf,     name="scan_pdf"),
    path("api/scan/",           views.ajax_scan,    name="ajax_scan"),
    path("api/metrics/",        views.ajax_metrics, name="ajax_metrics"),
]

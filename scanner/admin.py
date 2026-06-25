from django.contrib import admin
from .models import URLScan, ThreatReport, Recommendation


@admin.register(URLScan)
class URLScanAdmin(admin.ModelAdmin):
    list_display = ("url", "verdict", "threat_score", "user", "created_at")
    list_filter = ("verdict", "created_at")
    search_fields = ("url", "user__username")


@admin.register(ThreatReport)
class ThreatReportAdmin(admin.ModelAdmin):
    list_display = ("scan", "created_at")


@admin.register(Recommendation)
class RecommendationAdmin(admin.ModelAdmin):
    list_display = ("scan", "severity", "text")
    list_filter = ("severity",)

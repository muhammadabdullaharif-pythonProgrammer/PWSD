"""Database models for the cyber-detection engine."""
from django.conf import settings
from django.db import models


class URLScan(models.Model):
    VERDICT_CHOICES = [
        ("SAFE", "Safe"),
        ("SUSPICIOUS", "Suspicious"),
        ("PHISHING", "Phishing"),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                             related_name="scans")
    url = models.URLField(max_length=2048)
    verdict = models.CharField(max_length=16, choices=VERDICT_CHOICES, default="SAFE")
    threat_score = models.FloatField(default=0.0, help_text="0.0 – 100.0")
    features = models.JSONField(default=dict, blank=True)
    network = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["verdict"]),
                   models.Index(fields=["-created_at"])]

    def __str__(self) -> str:
        return f"{self.url} → {self.verdict} ({self.threat_score:.1f}%)"


class ThreatReport(models.Model):
    scan = models.OneToOneField(URLScan, on_delete=models.CASCADE,
                                related_name="report")
    summary = models.TextField()
    pdf_path = models.CharField(max_length=512, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"Report for {self.scan.url}"


class Recommendation(models.Model):
    scan = models.ForeignKey(URLScan, on_delete=models.CASCADE,
                             related_name="recommendations")
    text = models.CharField(max_length=300)
    severity = models.CharField(
        max_length=8,
        choices=[("LOW", "Low"), ("MED", "Medium"), ("HIGH", "High")],
        default="LOW",
    )

    def __str__(self) -> str:
        return f"[{self.severity}] {self.text}"

"""Scanner views — AJAX scan, history, dashboard analytics, PDF download."""
from __future__ import annotations
import json
import os
from collections import Counter
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import (
    JsonResponse, HttpResponse, HttpResponseForbidden, HttpResponseNotFound,
)
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from .models import URLScan, ThreatReport, Recommendation
from .utils.feature_extractor import extract_features
from .utils.classifier_model import classifier
from .utils.network_analyzer import analyse as network_analyse
from .utils.pdf_generator import build_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _build_recommendations(scan: URLScan) -> None:
    f = scan.features or {}
    recs: list[tuple[str, str]] = []
    if f.get("uses_ip"):
        recs.append(("HIGH", "Direct IP address detected — block at gateway."))
    if not f.get("uses_https"):
        recs.append(("MED", "Connection is not HTTPS — credentials at risk."))
    if f.get("has_at_symbol"):
        recs.append(("HIGH", "URL contains '@' — classic obfuscation pattern."))
    if f.get("is_shortener"):
        recs.append(("MED", "Shortened URL — expand before clicking."))
    if f.get("suspicious_keywords", 0) >= 2:
        recs.append(("HIGH", "Multiple suspicious keywords present."))
    if f.get("entropy", 0) > 4.2:
        recs.append(("MED", "High character entropy suggests randomised domain."))
    if scan.verdict == "PHISHING":
        recs.append(("HIGH", "Do NOT submit credentials. Report to IT/SOC team."))
    elif scan.verdict == "SUSPICIOUS":
        recs.append(("MED", "Treat as untrusted until manually verified."))
    else:
        recs.append(("LOW", "No critical risk indicators detected."))
    Recommendation.objects.bulk_create(
        [Recommendation(scan=scan, severity=s, text=t) for s, t in recs]
    )


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@login_required
def dashboard(request):
    return render(request, "scanner/dashboard.html", {"view": request.GET.get("view", "")})


@login_required
def history(request):
    qs = URLScan.objects.filter(user=request.user)         if not request.user.is_admin_role else URLScan.objects.all()
    return render(request, "scanner/history.html", {"scans": qs[:200]})


@login_required
def scan_detail(request, pk: int):
    scan = get_object_or_404(URLScan, pk=pk)
    if scan.user_id != request.user.id and not request.user.is_admin_role:
        return HttpResponseForbidden("Access denied.")
    return render(request, "scanner/scan_detail.html", {"scan": scan})


# ---------------------------------------------------------------------------
# AJAX endpoints
# ---------------------------------------------------------------------------
@login_required
@require_POST
def ajax_scan(request):
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    url = (payload.get("url") or "").strip()
    if not url or len(url) > 2048:
        return JsonResponse({"error": "URL is required (max 2048 chars)."},
                            status=400)

    features = extract_features(url)
    verdict, score = classifier.predict(features)
    network = network_analyse(url)

    scan = URLScan.objects.create(
        user=request.user, url=url, verdict=verdict,
        threat_score=score, features=features, network=network,
    )
    _build_recommendations(scan)

    ThreatReport.objects.create(
        scan=scan,
        summary=f"{verdict} ({score:.1f}%) — {len(features)} features evaluated.",
    )

    return JsonResponse({
        "id":           scan.id,
        "url":          scan.url,
        "verdict":      scan.verdict,
        "threat_score": scan.threat_score,
        "features":     scan.features,
        "network":      scan.network,
        "recommendations": [
            {"severity": r.severity, "text": r.text}
            for r in scan.recommendations.all()
        ],
        "detail_url":   f"/scanner/scan/{scan.id}/",
        "pdf_url":      f"/scanner/scan/{scan.id}/pdf/",
    })


@login_required
@require_GET
def ajax_metrics(request):
    """Aggregate metrics for the Chart.js dashboard widgets."""
    qs = URLScan.objects.all() if request.user.is_admin_role         else URLScan.objects.filter(user=request.user)

    verdicts = Counter(qs.values_list("verdict", flat=True))
    week_ago = timezone.now() - timedelta(days=7)
    recent = qs.filter(created_at__gte=week_ago)
    per_day = Counter(s.created_at.date().isoformat() for s in recent)

    return JsonResponse({
        "totals": {
            "all":        qs.count(),
            "safe":       verdicts.get("SAFE", 0),
            "suspicious": verdicts.get("SUSPICIOUS", 0),
            "phishing":   verdicts.get("PHISHING", 0),
        },
        "per_day":  dict(sorted(per_day.items())),
        "average_score": round(
            sum(s.threat_score for s in qs[:500]) / max(qs.count(), 1), 2
        ),
    })


# ---------------------------------------------------------------------------
# PDF download
# ---------------------------------------------------------------------------
@login_required
def scan_pdf(request, pk: int):
    scan = get_object_or_404(URLScan, pk=pk)
    if scan.user_id != request.user.id and not request.user.is_admin_role:
        return HttpResponseForbidden("Access denied.")

    media_dir = os.path.join(settings.MEDIA_ROOT, "reports")
    path = os.path.join(media_dir, f"pwds_report_{scan.id}.pdf")
    build_report(scan, path)

    if hasattr(scan, "report"):
        scan.report.pdf_path = path
        scan.report.save(update_fields=["pdf_path"])

    if not os.path.exists(path):
        return HttpResponseNotFound("PDF could not be generated.")
    with open(path, "rb") as fh:
        resp = HttpResponse(fh.read(), content_type="application/pdf")
    resp["Content-Disposition"] = f'attachment; filename="pwds_report_{scan.id}.pdf"'
    return resp

import json
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST, require_GET

from .ai_engine import ask
from .models import ChatbotLog


@login_required
@require_GET
def chat_page(request):
    history = ChatbotLog.objects.filter(user=request.user)[:25]
    return render(request, "chatbot/chat.html", {"history": history})


@login_required
@require_POST
def chat_api(request):
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    message = (body.get("message") or "").strip()
    if not message or len(message) > 1000:
        return JsonResponse({"error": "Message required (max 1000 chars)."},
                            status=400)

    result = ask(message)
    ChatbotLog.objects.create(
        user=request.user, question=message,
        answer=result["answer"], score=result["score"],
    )
    return JsonResponse(result)

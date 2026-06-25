from django.contrib import admin
from .models import ChatbotLog


@admin.register(ChatbotLog)
class ChatbotLogAdmin(admin.ModelAdmin):
    list_display = ("user", "question", "score", "created_at")
    search_fields = ("question", "answer", "user__username")

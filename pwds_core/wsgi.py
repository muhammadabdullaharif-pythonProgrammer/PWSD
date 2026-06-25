"""WSGI config for PWDS."""
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pwds_core.settings")
application = get_wsgi_application()

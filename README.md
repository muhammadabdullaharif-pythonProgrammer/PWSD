<<<<<<< HEAD
# Phishing Website Detection System (PWDS)

**Final Year Project — BS Computer Science (2022-2026)**

- **Student:** Muhammad Abdullah Arif
- **University:** Government College University Faisalabad
- **Department:** Department of Computer Science, Government Graduate College Jhang

## Overview

PWDS is an industrial-grade Django application that detects phishing
websites using lexical feature extraction, a Random-Forest-style
classifier, live WHOIS / DNS network intelligence, and an offline NLP
cybersecurity chatbot. Reports are generated as downloadable PDFs.

## Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | `accounts` | Custom user model with RBAC (Admin, Analyst, Standard) |
| 2 | `scanner` | URL submission, lexical feature extractor, classifier, history |
| 3 | `scanner.utils.network_analyzer` | Live WHOIS + DNS A/MX/NS lookups |
| 4 | `chatbot` | Offline cosine-similarity NLP assistant |
| 5 | `scanner.utils.pdf_generator` | Professional PDF forensic reports |

## Quick Start

```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open http://127.0.0.1:8000/ and sign up. The first registered user can be
promoted to `Admin` via `python manage.py shell`:

```python
from accounts.models import User
u = User.objects.get(username="yourname")
u.role = "ADMIN"; u.is_staff = True; u.is_superuser = True; u.save()
```

## Security Highlights

- PBKDF2 + Argon2 password hashing
- CSRF + secure-cookie + HSTS-ready settings
- Explicit XSS / clickjacking / referrer headers
- Role-based decorators on every protected view
- All scan input sanitised before feature extraction
=======
# PWSD
>>>>>>> 66f1ab12ec016d34023f3bdcb399af925a6a5196

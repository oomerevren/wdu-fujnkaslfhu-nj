# PentestAI — Production Ready Planı

> **Tarih:** 2026-07-21  
> **Hazırlayan:** CEO (Swarm Orchestrator)  
> **Kapsam:** Faz 1 MVP → Production Ready

---

## Mevcut Durum Özeti

| Alan | Durum |
|---|---|
| API Yapısı | ✅ Temiz FastAPI, service layer ayrışması var |
| Auth | ✅ JWT auth çalışıyor, onboarding flow var |
| Database | ✅ PostgreSQL, SQLAlchemy 2.0, Alembic migration |
| Workers | ⚠️ İskelet halinde, Nuclei simülasyon, ZAP ve PromptFoo kısmi |
| Ödeme | ⚠️ Stripe entegrasyon iskeleti var, webhook işlenmiyor |
| Test | ⚠️ Test suite var ama pytest değil, DB'ye bağlı |
| Güvenlik | ❌ JWT secret default, .env'de token var, rate limiter in-memory |
| Deployment | ❌ Dockerfile yok, CI/CD yok, monitoring yok |
| Logging | ❌ print() ile loglama, structured logging yok |

---

## Faz 1: Kritik Güvenlik (Hemen Yapılması Gerekenler)

### 1.1 Secret Management
- [ ] **JWT_SECRET_KEY** üret ve `.env`'e koy (şu an default)
- [ ] `.env`'den GitHub token'ını **kaldır** (hardcoded)
- [ ] `.env.example`'ı güncelle, production için uyarı ekle
- [ ] `pydantic-settings` ile environment-based config ekle (`ENV=development|staging|production`)

### 1.2 Auth Güvenliği
- [ ] Auth endpoint'lerine **rate limit** ekle (5 başarısız deneme / 15 dk)
- [ ] Brute force koruması: login başarısız sayısını takip et
- [ ] Password policy ekle (min 8 karakter, büyük/küçük/özel karakter)
- [ ] Email verification'ı aktifleştir (şu an TODO)
- [ ] Password reset email'ini aktifleştir (şu an TODO)

### 1.3 Dependency Security
- [ ] `pip-audit` ile bağımlılıkları tara
- [ ] `safety` ile vulnerability scan
- [ ] `requirements.txt`'deki versiyonları güncelle (en son kararlı sürümler)

---

## Faz 2: Altyapı & Deployment

### 2.1 Dockerfile
- [ ] Multi-stage Dockerfile (`python:3.12-slim`)
- [ ] Stage 1: builder (bağımlılıkları yükle)
- [ ] Stage 2: runner (minimal image)
- [ ] HEALTHCHECK instruction
- [ ] Non-root user (appuser)

### 2.2 Docker Compose (Production)
- [ ] Production docker-compose.yml (sadece postgres, redis)
- [ ] Worker'lar için ayrı service (celery worker)
- [ ] Nginx reverse proxy + SSL
- [ ] Volume yönetimi (pgdata, redis data)

### 2.3 Nginx Config
- [ ] SSL/TLS termination
- [ ] Rate limiting (nginx level)
- [ ] Request size limits
- [ ] CORS headers (production URL)
- [ ] Security headers (HSTS, CSP, X-Frame-Options)

### 2.4 CI/CD Pipeline
- [ ] GitHub Actions workflow
  - [ ] Lint (ruff)
  - [ ] Type check (pyright)
  - [ ] Test (pytest + coverage)
  - [ ] Build (Docker image)
  - [ ] Push to registry
  - [ ] Deploy (SSH/docker-compose)

---

## Faz 3: Veritabanı & Performans

### 3.1 Connection Pool
- [ ] SQLAlchemy pool ayarları (`pool_size=10, max_overflow=20, pool_timeout=30`)
- [ ] Connection recycling (`pool_recycle=3600`)
- [ ] `pool_pre_ping=True` (dead connection detection)

### 3.2 Indexing
- [ ] `findings.severity` index
- [ ] `findings.user_id + findings.severity` composite index
- [ ] `scans.user_id + scans.target_id` composite index
- [ ] `scans.created_at` descending index
- [ ] `targets.user_id` index

### 3.3 Migration Fixes
- [ ] `audit_logs.comment` alanını migration'a ekle (modelde yok ama migration'da var)
- [ ] Finding model'ine `comment` alanı ekle

### 3.4 Query Optimization
- [ ] N+1 fix: `Scan` query'de `joinedload(target)` kullan
- [ ] Finding list query'de pagination ekle (limit/offset)
- [ ] Scan list query'de pagination ekle

---

## Faz 4: Worker & Async Sistemi

### 4.1 Celery Entegrasyonu
- [ ] Celery app yapılandırması (Redis broker)
- [ ] Scan worker'larını Celery task'lerine dönüştür
- [ ] Task queue yönetimi (öncelik, concurrency)
- [ ] Result backend (Redis)
- [ ] Retry mekanizması (max_retries=3, exponential backoff)
- [ ] Task timeout yönetimi (soft/hard limit)

### 4.2 Worker İyileştirmeleri
- [ ] **Nuclei worker**: subprocess çağrısını aktifleştir
- [ ] **ZAP worker**: async HTTP polling kullan (blocking wait yerine)
- [ ] **PromptFoo worker**: tempfile cleanup'i düzelt (`'output_path' in dir()` -> try/except)
- [ ] Worker monitoring (task başarı/başarısızlık metrikleri)

### 4.3 WebSocket / Polling
- [ ] Scan progress için WebSocket endpoint
- [ ] Veya polling endpoint (`GET /scans/{id}/progress`)

---

## Faz 5: Monitoring & Logging

### 5.1 Structured Logging
- [ ] `loguru` veya `structlog` entegrasyonu
- [ ] JSON formatında loglama
- [ ] Request ID tracking (middleware)
- [ ] Log levels: DEBUG, INFO, WARNING, ERROR

### 5.2 Health Check
- [ ] `/health` -> DB, Redis, RabbitMQ bağlantılarını kontrol et
- [ ] `/health/ready` (readiness probe)
- [ ] `/health/live` (liveness probe)

### 5.3 Metrics
- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] Request count, latency, error rate
- [ ] Scan duration histogram
- [ ] Active users gauge

### 5.4 Error Tracking
- [ ] Sentry SDK entegrasyonu
- [ ] Global exception handler (FastAPI middleware)
- [ ] Unhandled exception logging

---

## Faz 6: Test Altyapısı

### 6.1 pytest Yapısı
- [ ] `pyproject.toml` oluştur (pytest config, ruff config)
- [ ] Test database fixture (SQLite in-memory veya testcontainers)
- [ ] Auth fixture (test user + token)
- [ ] Coverage config (`--cov=app --cov-report=term-missing`)

### 6.2 Test Senaryoları
- [ ] **Unit tests**: service layer (auth_service, report_service)
- [ ] **API tests**: tüm endpoint'ler (auth, targets, scans, findings, reports, subscriptions)
- [ ] **Integration tests**: worker → DB flow
- [ ] **Security tests**: JWT manipulation, SQL injection, XSS
- [ ] **Performance tests**: locust veya k6 scripti

---

## Faz 7: API & Kod Kalitesi

### 7.1 API İyileştirmeleri
- [ ] Tüm hata mesajlarını **İngilizce** yap (şu an karışık Türkçe/İngilizce)
- [ ] Global exception handler (tüm HTTPException'ları consistent formatta döndür)
- [ ] Request validation için Pydantic v2 özelliklerini kullan
- [ ] Response model'lerinde `model_validate` yerine `from_orm` kullanımını düzelt
- [ ] Pagination response schema (page, size, total, items)

### 7.2 Stripe Webhook
- [ ] Webhook event processing'i tamamla:
  - [ ] `checkout.session.completed` -> subscription oluştur
  - [ ] `customer.subscription.updated` -> plan değişikliği
  - [ ] `customer.subscription.deleted` -> subscription iptal
  - [ ] `invoice.paid` -> ödeme başarılı
  - [ ] `invoice.payment_failed` -> ödeme başarısız

### 7.3 Audit Log
- [ ] Finding status değişikliklerini audit_log'a kaydet
- [ ] Login/logout event'lerini logla
- [ ] Scan create/complete event'lerini logla
- [ ] Admin actions log

---

## Faz 8: Ödeme & Subscription

### 8.1 Plan Yönetimi
- [ ] Plan feature mapping (scans_limit, users_limit, api_access vs.)
- [ ] Plan upgrade/downgrade logic
- [ ] Usage tracking (scans_used reset per billing period)

### 8.2 Stripe Production
- [ ] Production price ID'lerini güncelle
- [ ] Webhook secret rotation
- [ ] Test webhook events ile doğrulama

---

## Faz 9: Final Güvenlik Auditi

### 9.1 Security Checklist
- [ ] SQL injection koruması (SQLAlchemy parameterized queries — zaten var)
- [ ] XSS koruması (Jinja2 autoescaping — kontrol et)
- [ ] CSRF koruması (CORS + SameSite cookies)
- [ ] JWT token rotation (refresh token mekanizması)
- [ ] API key rate limiting (token bazlı)
- [ ] File upload güvenliği (ilerde eklenecekse)
- [ ] Docker security scanning (trivy)

### 9.2 Penetrasyon Testi
- [ ] OWASP Top 10 kontrolü
- [ ] API endpoint fuzzing
- [ ] Auth bypass testleri

---

## Implementation Roadmap

```
Hafta 1: Faz 1 (Kritik Güvenlik) + Faz 3.1 (Connection Pool)
Hafta 2: Faz 4 (Worker & Async) + Faz 3.2-3.4 (Index/Pagination)
Hafta 3: Faz 5 (Monitoring & Logging) + Faz 2 (Docker/Deploy)
Hafta 4: Faz 6 (Test) + Faz 7 (API Kalitesi)
Hafta 5: Faz 8 (Ödeme) + Faz 9 (Security Audit)
```

---

## Hemen Başlanacaklar (Acil)

| # | Task | Etki |
|---|---|---|
| 1 | JWT secret key değiştir | 🔴 Critical |
| 2 | GitHub token'ı .env'den kaldır | 🔴 Critical |
| 3 | Auth rate limiting | 🟠 High |
| 4 | Email verification'ı aktifleştir | 🟠 High |
| 5 | Structured logging ekle | 🟠 High |
| 6 | Dockerfile oluştur | 🟡 Medium |
| 7 | pytest altyapısı kur | 🟡 Medium |
| 8 | Health check'i zenginleştir | 🟡 Medium |
| 9 | Celery worker geçişi | 🟡 Medium |
| 10 | Error messages İngilizce | 🟢 Low |

---

*Bu plan swarm orchestrator tarafından hazırlanmıştır. Her faz için paralel task'ler oluşturulup uygun agent'lara dağıtılabilir.*

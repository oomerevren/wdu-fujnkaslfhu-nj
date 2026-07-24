# PentestAI — AI Destekli Otonom Siber Güvenlik Platformu

> **Durum:** Faz 1 MVP — Production Ready (2 aylık exit planı kapsamında)
> **Lisans:** Özel Mülkiyet (Open-source değil)
> **Teknoloji:** Python 3.12, FastAPI, SQLAlchemy 2.0, PostgreSQL, Redis, RabbitMQ, Celery, Neo4j, Docker, Nginx

---

## Özellikler
- **AI Destekli Otonom Tarama:** LangGraph tabanlı `PentestOrchestrator` (recon → plan → execute → exploit → analyze → report)
- **Agent Sistemi:** `ReconAgent`, `ScannerAgent`, `ExploitAgent`, `AnalyzerAgent`, `KnowledgeGraph` (Neo4j)
- **Güvenlik:** JWT HS512, refresh token rotation, token blacklist (Redis), brute-force koruması, rate limiting, CORS, security headers, SSL/TLS
- **Ödeme:** Stripe (abone, checkout, webhook — `checkout.session.completed`, `invoice.paid`, `customer.subscription.updated/deleted`)
- **Planlar:** FREE (1 scan), STARTER ($99/ay), SOLO ($199/ay), PRO ($499/ay), ENTERPRISE (özel)
- **Deployment:** Blue-green (`deploy.sh`), Docker Compose production, CI/CD (`.github/workflows/`), Nginx reverse proxy
- **SDK & CLI:** Python SDK (`sdk/`), CLI (`cli/`)
- **Monitoring:** Prometheus metrics, OpenTelemetry tracing, structured logging (JSON)
- **Test:** pytest (`tests/` — `test_api.py`, `test_scan_tasks.py`, `test_health.py`, `test_rate_limiter.py`, `test_security.py`, `test_cvss_score.py`)

---

## SaaS Planı (Sıfır Maliyet)
- **Altyapı:** AWS EC2 t3.micro / GCP e2-micro (Free Tier), RDS PostgreSQL / Cloud SQL f1-micro, Docker Compose
- **SSL:** Let's Encrypt (ücretsiz)
- **Gelir:** Stripe üzerinden aylık abonelik (MRR)
- **Hedef:** 2 ayda exit (satın alma veya stratejik ortaklık) — hedef fiyat $10K-$50K

---

## Kurulum (Production)

1. `.env` dosyasını kopyalayın ve `.env` olarak güncelleyin:
   ```bash
   cp .env.example .env
   # .env dosyasını kendi production değerlerinizle güncelleyin
   # ÖNEMLİ: JWT_SECRET_KEY en az 64 karakter, 1 rakam, 1 özel karakter içermeli!
   ```

2. Docker konteynerlarını başlatın:
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

3. Bağımlılıkları yükleyin:
   ```bash
   pip install -r requirements.txt
   ```

4. Veritabanı migration'larını çalıştırın:
   ```bash
   alembic upgrade head
   ```

5. Uygulamayı çalıştırın:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

---

## API Dokümantasyonu
Uygulama çalıştıktan sonra `https://app.pentestai.com/docs` adresinden Swagger UI'a erişebilirsiniz.

---

## Exit Planı (2 Ay)
- **Ay 1:** Ürün tamamlama (kritik güvenlik, altyapı, deployment, test) + ilk müşteriler
- **Ay 2:** Müşteri edinimi (hedef: 5-20 ödeme yapan müşteri, MRR $500-$2,000) + exit dokümantasyonu + potansiyel alıcılarla görüşmeler
- **Hedef:** Ürünü (kod + veritabanı + AI agent'ler + müşteri listesi + marka) satmak veya stratejik ortaklık kurmak.

---

## Repo Düzeni
```
.
├── .env / .env.example
├── Dockerfile / Dockerfile.worker
├── docker-compose.prod.yml / docker-compose.yml / docker-compose.monitoring.yml
├── deploy.sh (blue-green deployment)
├── nginx.conf (production SSL, rate limiting, security headers)
├── requirements.txt / requirements-lock.txt / uv.lock / pyproject.toml
├── app/ (FastAPI backend — agents, ai, api, services, workers, tasks, events, middleware, schemas, telemetry, plugins, workflows)
├── sdk/ (Python SDK — client.py, models.py, setup.py)
├── cli/ (CLI — main.py)
├── tests/ (pytest — test_api.py, test_scan_tasks.py, test_health.py, test_rate_limiter.py, test_security.py, test_cvss_score.py)
├── .github/workflows/ (CI/CD — lint, test, docker-build, security-scan, deploy-staging, deploy-production)
├── integrations/ (GitHub Actions — action.yml)
└── docs/ (PRODUCTION_READY_PLAN.md, DETAYLI_DEGERLENDIRME_VE_SAAS_PLANI.md)
```

---

*Not: Bu proje özel mülkiyettedir. Open-source değildir. GitHub'a yüklenme nedeni sadece inceleme amaçlıdır.*

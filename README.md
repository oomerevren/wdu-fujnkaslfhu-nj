# PentestAI Backend - Faz 1

Bu proje PentestAI platformunun MVP backend aşamasını içerir.

## Özellikler
- FastAPI ile RESTful API
- PostgreSQL veritabanı (SQLAlchemy 2.0)
- JWT tabanlı Auth sistemi
- Kullanıcı Onboarding akışı
- Hedef (Target) ve Tarama (Scan) yönetimi
- Nuclei ve ZAP entegrasyonu (Worker iskeletleri)
- Bulgu (Finding) dashboardu ve istatistikleri
- PDF Rapor motoru iskeleti
- Stripe ödeme entegrasyonu iskeleti
- Rate limiting ve güvenlik önlemleri

## Kurulum

1. Docker konteynerlarını başlatın:
   ```bash
   docker-compose up -d
   ```

2. Bağımlılıkları yükleyin:
   ```bash
   pip install -r requirements.txt
   ```

3. Veritabanı migration'larını çalıştırın:
   ```bash
   cd backend
   alembic upgrade head
   ```

4. Uygulamayı çalıştırın:
   ```bash
   uvicorn app.main:app --reload
   ```

## API Dokümantasyonu
Uygulama çalıştıktan sonra `http://localhost:8000/docs` adresinden Swagger UI'a erişebilirsiniz.

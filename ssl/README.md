# SSL Certificates

Place your production SSL certificates here:
- fullchain.pem
- privkey.pem

For development/test, use self-signed certificates or Let's Encrypt (certbot).

Example (self-signed):
```bash
openssl req -x509 -newkey rsa:4096 -keyout privkey.pem -out fullchain.pem -days 365 -nodes -subj "/CN=pentestai.com"
```

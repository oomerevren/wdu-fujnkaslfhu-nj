"""Direct test of register function to find the 500 error."""
import sys
sys.path.insert(0, r'C:\Users\ömer\Documents\Default Project\faz1')

from app.database import SessionLocal
from app.services.auth_service import register_user

try:
    db = SessionLocal()
    user = register_user(db, 'direct@test.com', 'Test123!', 'Direct Test')
    print(f'User created: {user.id} {user.email}')
except Exception as e:
    import traceback
    traceback.print_exc()
finally:
    db.close()

import time
from uuid import UUID, uuid4
import pytest
from fastapi import HTTPException
from app.services.auth_service import (
    create_refresh_token,
    refresh_access_token,
    revoke_all_user_refresh_tokens,
)
from app.utils.token_blacklist import token_blacklist
from app.utils.key_rotation import key_manager
from app.models.user import User

def test_refresh_token_rotation_replay_revokes_all(db_session, test_user):
    # 1. Create a refresh token
    jti1 = str(uuid4())
    rt1 = create_refresh_token(test_user.id, jti=jti1)
    token_blacklist.store_refresh_token(jti1, str(test_user.id), 3600)
    
    # Verify it is active
    assert token_blacklist.get_refresh_token_status(jti1) == "active"
    
    # 2. Refresh it
    resp = refresh_access_token(rt1, db_session)
    assert resp.access_token is not None
    assert resp.refresh_token is not None
    
    # Old token should now be marked "used"
    assert token_blacklist.get_refresh_token_status(jti1) == "used"
    
    # Get the new refresh token's jti from active list
    if token_blacklist._is_redis_up():
        user_jtis = token_blacklist.redis.smembers(f"user_rt:{test_user.id}")
        user_jtis = [j.decode() if isinstance(j, bytes) else j for j in user_jtis]
    else:
        user_jtis = list(token_blacklist._mem_user_rt.get(str(test_user.id), set()))
        
    # There should be only one active/used token in the user's set (the new one)
    # Note that old one might still be in the set if we check mem_user_rt or Redis.
    # In token_blacklist:
    # store_refresh_token: pipe.sadd(f"user_rt:{user_id}", jti)
    # revoke_all_user_tokens: pipe.delete(f"user_rt:{user_id}")
    # get_refresh_token_status(jti) for new jti will be "active"
    active_jtis = [j for j in user_jtis if token_blacklist.get_refresh_token_status(j) == "active"]
    assert len(active_jtis) == 1
    new_jti_val = active_jtis[0]
    
    # 3. Attempt to use the old token again (replay)
    with pytest.raises(HTTPException) as exc:
        refresh_access_token(rt1, db_session)
        
    assert exc.value.status_code == 401
    
    # 4. Verify that ALL refresh tokens for the user are now revoked
    assert token_blacklist.get_refresh_token_status(jti1) == "revoked"
    assert token_blacklist.get_refresh_token_status(new_jti_val) == "revoked"

def test_key_rotation_manager():
    # Test key manager automatic rotation
    initial_rotation_time = key_manager._mem_last_rotation_time
    assert initial_rotation_time is not None
    
    # age threshold not reached, should not rotate
    rotated = key_manager.check_and_rotate_key(max_age_seconds=100)
    assert not rotated
    assert key_manager._mem_last_rotation_time == initial_rotation_time
    
    # age threshold reached (simulate by setting creation time in past)
    key_manager._mem_last_rotation_time = time.time() - 200
    if key_manager._is_redis_up():
        key_manager.redis.set("jwt:last_rotation_time", str(time.time() - 200))
        
    rotated = key_manager.check_and_rotate_key(max_age_seconds=100)
    assert rotated
    assert key_manager._mem_last_rotation_time > initial_rotation_time

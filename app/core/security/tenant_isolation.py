
import uuid
from contextvars import ContextVar
from typing import Optional, List

# ContextVar to hold the tenant ID for the current execution flow
tenant_context: ContextVar[Optional[str]] = ContextVar('tenant_id', default=None)

class RBACManager:
    ROLES = {
        'admin': ['scan:start', 'scan:view', 'org:manage', 'user:invite'],
        'auditor': ['scan:view'],
        'operator': ['scan:start', 'scan:view']
    }

    @staticmethod
    def has_permission(role: str, action: str) -> bool:
        return action in RBACManager.ROLES.get(role, [])

class TenantContext:
    @staticmethod
    def set_tenant(tenant_id: str):
        tenant_context.set(tenant_id)
        print(f'[Security] Context set for Tenant: {tenant_id}')

    @staticmethod
    def get_tenant() -> Optional[str]:
        return tenant_context.get()

    @staticmethod
    def validate_isolation(resource_owner_id: str):
        current_tenant = TenantContext.get_tenant()
        if current_tenant != resource_owner_id:
            raise PermissionError(f'Access Denied: Resource belongs to {resource_owner_id}, current context is {current_tenant}')
        return True

class MTLSValidator:
    @staticmethod
    def verify_cert(cert_serial: str, client_id: str) -> bool:
        # Simulation of mTLS handshake validation
        print(f'[mTLS] Verifying certificate {cert_serial} for client {client_id}')
        return True

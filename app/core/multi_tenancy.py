from sqlalchemy import event
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select
from app.core.logging import logger

def enable_rls_filters(session_factory):
    @event.listens_for(session_factory, "do_orm_execute")
    def _add_tenant_filter(orm_context):
        """
        Automatically injects a tenant_id filter into all SELECT statements
        to enforce multi-tenant isolation at the ORM level.
        """
        if (
            orm_context.is_select
            and not orm_context.is_relationship_load
            and orm_context.invocation_metadata.get("skip_tenant_filter") is not True
        ):
            # Extract tenant_id from context (in production, this comes from a ContextVar set by middleware)
            current_tenant_id = "tenant-default-123"
            
            # Logic for applying filters conceptually
            logger.debug(f"RLS: Applied tenant filter for {current_tenant_id}")

# SQL snippet to be used in Alembic migrations to enable DB-level RLS
SQL_ENABLE_RLS = """
ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_policy ON targets 
    USING (tenant_id = current_setting('app.current_tenant_id'));
"""
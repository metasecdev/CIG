"""
Multi-tenant support for CIG
"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import uuid
import logging

logger = logging.getLogger(__name__)


@dataclass
class TenantConfig:
    """Tenant configuration"""
    tenant_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    enabled: bool = True
    database_path: str = ""
    feeds_enabled: List[str] = field(default_factory=list)
    api_key: str = field(default_factory=lambda: str(uuid.uuid4()))
    rate_limit: int = 1000  # API calls per hour
    storage_limit_gb: int = 100
    retention_days: int = 90
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "database_path": self.database_path,
            "feeds_enabled": self.feeds_enabled,
            "rate_limit": self.rate_limit,
            "storage_limit_gb": self.storage_limit_gb,
            "retention_days": self.retention_days,
        }


class TenantContext:
    """Thread-local tenant context"""

    def __init__(self):
        self._current_tenant: Optional[str] = None

    def set_tenant(self, tenant_id: str) -> None:
        """Set current tenant"""
        self._current_tenant = tenant_id

    def get_tenant(self) -> Optional[str]:
        """Get current tenant"""
        return self._current_tenant

    def clear(self) -> None:
        """Clear tenant context"""
        self._current_tenant = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()


class TenantManager(ABC):
    """Abstract base class for tenant management"""

    @abstractmethod
    def create_tenant(self, config: TenantConfig) -> str:
        """Create a new tenant"""
        pass

    @abstractmethod
    def get_tenant(self, tenant_id: str) -> Optional[TenantConfig]:
        """Get tenant configuration"""
        pass

    @abstractmethod
    def update_tenant(self, tenant_id: str, config: TenantConfig) -> bool:
        """Update tenant configuration"""
        pass

    @abstractmethod
    def delete_tenant(self, tenant_id: str) -> bool:
        """Delete a tenant"""
        pass

    @abstractmethod
    def list_tenants(self) -> List[TenantConfig]:
        """List all tenants"""
        pass

    @abstractmethod
    def get_tenant_by_api_key(self, api_key: str) -> Optional[TenantConfig]:
        """Get tenant by API key"""
        pass


class InMemoryTenantManager(TenantManager):
    """In-memory tenant manager"""

    def __init__(self):
        self.tenants: Dict[str, TenantConfig] = {}
        self.api_key_index: Dict[str, str] = {}

    def create_tenant(self, config: TenantConfig) -> str:
        """Create a new tenant"""
        self.tenants[config.tenant_id] = config
        self.api_key_index[config.api_key] = config.tenant_id
        logger.info(f"Tenant created: {config.tenant_id} ({config.name})")
        return config.tenant_id

    def get_tenant(self, tenant_id: str) -> Optional[TenantConfig]:
        """Get tenant configuration"""
        return self.tenants.get(tenant_id)

    def update_tenant(self, tenant_id: str, config: TenantConfig) -> bool:
        """Update tenant configuration"""
        if tenant_id not in self.tenants:
            return False

        old_key = self.tenants[tenant_id].api_key
        if old_key in self.api_key_index:
            del self.api_key_index[old_key]

        self.tenants[tenant_id] = config
        self.api_key_index[config.api_key] = tenant_id
        logger.info(f"Tenant updated: {tenant_id}")
        return True

    def delete_tenant(self, tenant_id: str) -> bool:
        """Delete a tenant"""
        if tenant_id not in self.tenants:
            return False

        config = self.tenants[tenant_id]
        del self.tenants[tenant_id]
        
        if config.api_key in self.api_key_index:
            del self.api_key_index[config.api_key]

        logger.info(f"Tenant deleted: {tenant_id}")
        return True

    def list_tenants(self) -> List[TenantConfig]:
        """List all tenants"""
        return list(self.tenants.values())

    def get_tenant_by_api_key(self, api_key: str) -> Optional[TenantConfig]:
        """Get tenant by API key"""
        tenant_id = self.api_key_index.get(api_key)
        if tenant_id:
            return self.tenants.get(tenant_id)
        return None


class TenantDataFilter:
    """Filter data by tenant"""

    def __init__(self, tenant_context: TenantContext):
        self.context = tenant_context

    def add_tenant_to_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add tenant ID to data"""
        tenant_id = self.context.get_tenant()
        if tenant_id:
            data["tenant_id"] = tenant_id
        return data

    def filter_by_tenant(self, data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter data list by current tenant"""
        tenant_id = self.context.get_tenant()
        if not tenant_id:
            return data_list

        return [item for item in data_list if item.get("tenant_id") == tenant_id]

    def where_clause(self, include_tenant: bool = True) -> str:
        """Get SQL WHERE clause for tenant"""
        tenant_id = self.context.get_tenant()
        if not tenant_id or not include_tenant:
            return ""
        return f"tenant_id = '{tenant_id}'"


class MultiTenantDatabase:
    """Multi-tenant database wrapper"""

    def __init__(self, db, tenant_context: TenantContext):
        """
        Initialize multi-tenant database.
        
        Args:
            db: Underlying database connection
            tenant_context: Tenant context
        """
        self.db = db
        self.context = tenant_context
        self.filter = TenantDataFilter(tenant_context)

    def insert_alert(self, alert: Any) -> None:
        """Insert alert for current tenant"""
        alert_data = alert.to_dict() if hasattr(alert, 'to_dict') else alert
        alert_data = self.filter.add_tenant_to_data(alert_data)
        # Call underlying database
        self.db.insert_alert(alert_data)

    def get_alerts(self, **kwargs) -> List[Any]:
        """Get alerts for current tenant"""
        # Would need to modify underlying query
        all_alerts = self.db.get_alerts(**kwargs)
        return self.filter.filter_by_tenant(all_alerts)

    def insert_indicator(self, indicator: Any) -> None:
        """Insert indicator for current tenant"""
        indicator_data = indicator.to_dict() if hasattr(indicator, 'to_dict') else indicator
        indicator_data = self.filter.add_tenant_to_data(indicator_data)
        self.db.insert_indicator(indicator_data)

    def get_indicators(self, **kwargs) -> List[Any]:
        """Get indicators for current tenant"""
        all_indicators = self.db.get_indicators(**kwargs)
        return self.filter.filter_by_tenant(all_indicators)


class TenantUsageTracker:
    """Track tenant resource usage"""

    def __init__(self):
        self.usage: Dict[str, Dict[str, Any]] = {}

    def record_api_call(self, tenant_id: str) -> None:
        """Record API call for tenant"""
        if tenant_id not in self.usage:
            self.usage[tenant_id] = {
                "api_calls": 0,
                "storage_bytes": 0,
                "alerts_created": 0,
            }
        self.usage[tenant_id]["api_calls"] += 1

    def record_storage(self, tenant_id: str, bytes_used: int) -> None:
        """Record storage usage"""
        if tenant_id not in self.usage:
            self.usage[tenant_id] = {
                "api_calls": 0,
                "storage_bytes": 0,
                "alerts_created": 0,
            }
        self.usage[tenant_id]["storage_bytes"] = bytes_used

    def record_alert(self, tenant_id: str) -> None:
        """Record alert creation"""
        if tenant_id not in self.usage:
            self.usage[tenant_id] = {
                "api_calls": 0,
                "storage_bytes": 0,
                "alerts_created": 0,
            }
        self.usage[tenant_id]["alerts_created"] += 1

    def get_usage(self, tenant_id: str) -> Dict[str, Any]:
        """Get tenant usage"""
        return self.usage.get(tenant_id, {})

    def get_all_usage(self) -> Dict[str, Dict[str, Any]]:
        """Get all tenant usage"""
        return self.usage.copy()

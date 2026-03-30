"""
Threat response automation system
"""

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import logging
import json

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of automated response actions"""
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    ISOLATE_HOST = "isolate_host"
    QUARANTINE_FILE = "quarantine_file"
    CREATE_TICKET = "create_ticket"
    SEND_ALERT = "send_alert"
    GATHER_FORENSICS = "gather_forensics"
    KILL_PROCESS = "kill_process"
    TERMINATE_SESSION = "terminate_session"


@dataclass
class PlaybookAction:
    """Single action in an automation playbook"""
    action_type: ActionType
    target: str  # IP, domain, host, file, etc.
    parameters: Dict[str, Any] = None
    enabled: bool = True
    description: str = ""

    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action_type.value,
            "target": self.target,
            "parameters": self.parameters,
            "enabled": self.enabled,
            "description": self.description,
        }


@dataclass
class Playbook:
    """Automated response playbook"""
    name: str
    description: str
    trigger_severity: str  # critical, high, medium, low
    actions: List[PlaybookAction]
    enabled: bool = True
    approval_required: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "trigger_severity": self.trigger_severity,
            "actions": [a.to_dict() for a in self.actions],
            "enabled": self.enabled,
            "approval_required": self.approval_required,
        }


class ActionHandler:
    """Base class for action handlers"""

    async def execute(self, action: PlaybookAction) -> bool:
        """Execute action. Return True if successful."""
        raise NotImplementedError

    async def rollback(self, action: PlaybookAction) -> bool:
        """Rollback action if needed"""
        return True


class FirewallActionHandler(ActionHandler):
    """Handle firewall-based blocking actions"""

    def __init__(self, firewall_api: Optional[str] = None):
        self.firewall_api = firewall_api

    async def execute(self, action: PlaybookAction) -> bool:
        """Execute firewall action"""
        try:
            if action.action_type == ActionType.BLOCK_IP:
                return await self._block_ip(action.target, action.parameters)
            elif action.action_type == ActionType.BLOCK_DOMAIN:
                return await self._block_domain(action.target, action.parameters)
            return False
        except Exception as e:
            logger.error(f"Firewall action failed: {e}")
            return False

    async def _block_ip(self, ip: str, params: Dict[str, Any]) -> bool:
        """Block IP in firewall"""
        logger.info(f"[MOCK] Blocking IP: {ip} (params: {params})")
        # In production, integrate with actual firewall API
        return True

    async def _block_domain(self, domain: str, params: Dict[str, Any]) -> bool:
        """Block domain in DNS/proxy"""
        logger.info(f"[MOCK] Blocking domain: {domain} (params: {params})")
        return True


class NotificationActionHandler(ActionHandler):
    """Handle notification actions"""

    async def execute(self, action: PlaybookAction) -> bool:
        """Send notifications"""
        try:
            if action.action_type == ActionType.SEND_ALERT:
                return await self._send_alert(action.target, action.parameters)
            elif action.action_type == ActionType.CREATE_TICKET:
                return await self._create_ticket(action.target, action.parameters)
            return False
        except Exception as e:
            logger.error(f"Notification action failed: {e}")
            return False

    async def _send_alert(self, recipient: str, params: Dict[str, Any]) -> bool:
        """Send alert notification"""
        logger.info(f"[MOCK] Sending alert to: {recipient}")
        return True

    async def _create_ticket(self, system: str, params: Dict[str, Any]) -> bool:
        """Create incident ticket"""
        logger.info(f"[MOCK] Creating ticket in {system}")
        return True


class ForensicsActionHandler(ActionHandler):
    """Handle forensic data collection"""

    async def execute(self, action: PlaybookAction) -> bool:
        """Collect forensic data"""
        try:
            if action.action_type == ActionType.GATHER_FORENSICS:
                return await self._gather_forensics(action.target, action.parameters)
            return False
        except Exception as e:
            logger.error(f"Forensics action failed: {e}")
            return False

    async def _gather_forensics(self, target: str, params: Dict[str, Any]) -> bool:
        """Gather forensic data from target"""
        logger.info(f"[MOCK] Gathering forensics from: {target}")
        return True


class ResponseAutomation:
    """Threat response automation engine"""

    def __init__(self):
        """Initialize response automation"""
        self.playbooks: Dict[str, Playbook] = {}
        self.handlers: Dict[ActionType, ActionHandler] = {
            ActionType.BLOCK_IP: FirewallActionHandler(),
            ActionType.BLOCK_DOMAIN: FirewallActionHandler(),
            ActionType.SEND_ALERT: NotificationActionHandler(),
            ActionType.CREATE_TICKET: NotificationActionHandler(),
            ActionType.GATHER_FORENSICS: ForensicsActionHandler(),
        }
        self.action_history: List[Dict[str, Any]] = []

    def register_playbook(self, playbook: Playbook) -> None:
        """Register an automation playbook"""
        self.playbooks[playbook.name] = playbook
        logger.info(f"Playbook registered: {playbook.name}")

    def get_playbook(self, name: str) -> Optional[Playbook]:
        """Get playbook by name"""
        return self.playbooks.get(name)

    def get_applicable_playbooks(self, severity: str) -> List[Playbook]:
        """Get playbooks applicable to alert severity"""
        applicable = []
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        alert_level = severity_order.get(severity, 4)

        for playbook in self.playbooks.values():
            if not playbook.enabled:
                continue
            playbook_level = severity_order.get(playbook.trigger_severity, 4)
            if alert_level <= playbook_level:
                applicable.append(playbook)

        return applicable

    async def execute_playbook(self, playbook: Playbook, alert_data: Dict[str, Any],
                              approval_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Execute automation playbook.
        
        Args:
            playbook: Playbook to execute
            alert_data: Alert data triggering playbook
            approval_callback: Optional approval callback for approval_required playbooks
        
        Returns:
            Execution results
        """
        if not playbook.enabled:
            return {"success": False, "reason": "Playbook disabled"}

        if playbook.approval_required and approval_callback:
            if not await approval_callback(playbook, alert_data):
                return {"success": False, "reason": "Approval denied"}

        results = {"playbook": playbook.name, "actions": []}

        for action in playbook.actions:
            if not action.enabled:
                continue

            handler = self.handlers.get(action.action_type)
            if not handler:
                logger.warning(f"No handler for action: {action.action_type}")
                results["actions"].append({
                    "action": action.action_type.value,
                    "target": action.target,
                    "success": False,
                    "reason": "No handler"
                })
                continue

            success = await handler.execute(action)
            results["actions"].append({
                "action": action.action_type.value,
                "target": action.target,
                "success": success,
            })

            # Record action
            self.action_history.append({
                "playbook": playbook.name,
                "action": action.action_type.value,
                "target": action.target,
                "success": success,
                "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
                "alert": alert_data.get("id", "unknown"),
            })

        return {"success": True, "results": results}

    async def execute_automatic_response(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute automatic response for alert"""
        severity = alert_data.get("severity", "low")
        playbooks = self.get_applicable_playbooks(severity)

        if not playbooks:
            logger.info(f"No playbooks for severity: {severity}")
            return {"success": False, "reason": "No applicable playbooks"}

        # Execute first applicable playbook
        playbook = playbooks[0]
        return await self.execute_playbook(playbook, alert_data)

    def get_action_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get action execution history"""
        return self.action_history[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get automation statistics"""
        total_actions = len(self.action_history)
        successful = sum(1 for a in self.action_history if a.get("success"))

        return {
            "total_playbooks": len(self.playbooks),
            "enabled_playbooks": sum(1 for p in self.playbooks.values() if p.enabled),
            "total_actions": total_actions,
            "successful_actions": successful,
            "success_rate": (successful / total_actions * 100) if total_actions > 0 else 0,
            "actions_by_type": self._count_by_type("action"),
        }

    def _count_by_type(self, field: str) -> Dict[str, int]:
        """Count something by type"""
        counts = {}
        for item in self.action_history:
            key = item.get(field, "unknown")
            counts[key] = counts.get(key, 0) + 1
        return counts

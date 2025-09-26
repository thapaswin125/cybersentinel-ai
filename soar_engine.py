"""
CyberSentinel AI - SOAR Automation Engine
Security Orchestration, Automation and Response system
"""

import json
import asyncio
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional
import logging
import uuid

class IncidentSeverity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class PlaybookStatus(Enum):
    IDLE = "Idle"
    RUNNING = "Running"
    SUCCESS = "Success"
    FAILED = "Failed"
    PAUSED = "Paused"

class ActionResult(Enum):
    SUCCESS = "Success"
    FAILED = "Failed"
    TIMEOUT = "Timeout"
    PENDING = "Pending"

@dataclass
class SecurityIncident:
    """Security incident data structure"""
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    source_ip: str = ""
    target_ip: str = ""
    attack_type: str = ""
    created_at: str = ""
    updated_at: str = ""
    status: str = "Open"
    assigned_playbook: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

@dataclass
class PlaybookAction:
    """Individual action within a playbook"""
    id: str
    name: str
    action_type: str
    parameters: Dict[str, Any]
    timeout: int = 60
    retry_count: int = 0
    max_retries: int = 3
    depends_on: List[str] = None

    def __post_init__(self):
        if self.depends_on is None:
            self.depends_on = []

class SOAREngine:
    """
    Security Orchestration, Automation and Response Engine
    """

    def __init__(self):
        self.incidents: Dict[str, SecurityIncident] = {}
        self.playbooks: Dict[str, Dict] = {}
        self.active_executions: Dict[str, Dict] = {}

        # Configure logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # Initialize default playbooks
        self.initialize_default_playbooks()

        # Integration endpoints (mock)
        self.integrations = {
            'firewall': {'endpoint': 'https://firewall.api/v1/', 'auth': 'api_key'},
            'siem': {'endpoint': 'https://siem.api/v1/', 'auth': 'bearer_token'},
            'edr': {'endpoint': 'https://edr.api/v1/', 'auth': 'api_key'},
            'email_gateway': {'endpoint': 'https://email.api/v1/', 'auth': 'oauth2'}
        }

    def initialize_default_playbooks(self):
        """Initialize default incident response playbooks"""

        # DDoS Response Playbook
        ddos_playbook = {
            'id': 'ddos_response',
            'name': 'DDoS Attack Response',
            'description': 'Automated response to DDoS attacks',
            'trigger_conditions': ['attack_type:ddos', 'severity:high,critical'],
            'actions': [
                PlaybookAction(
                    id='block_source_ip',
                    name='Block Source IP at Firewall',
                    action_type='firewall_block',
                    parameters={'ip_list': '{{incident.source_ip}}', 'rule_name': 'DDoS_Block_{{incident.id}}'}
                ),
                PlaybookAction(
                    id='rate_limit_enable',
                    name='Enable Rate Limiting',
                    action_type='rate_limit',
                    parameters={'target': '{{incident.target_ip}}', 'limit': 100},
                    depends_on=['block_source_ip']
                ),
                PlaybookAction(
                    id='notify_soc',
                    name='Notify SOC Team',
                    action_type='notification',
                    parameters={'channel': 'slack', 'message': 'DDoS attack detected and blocked'},
                    depends_on=['rate_limit_enable']
                )
            ]
        }

        # Malware Response Playbook
        malware_playbook = {
            'id': 'malware_containment',
            'name': 'Malware Containment and Analysis',
            'description': 'Automated malware containment and forensic analysis',
            'trigger_conditions': ['attack_type:malware', 'severity:medium,high,critical'],
            'actions': [
                PlaybookAction(
                    id='isolate_host',
                    name='Isolate Infected Host',
                    action_type='edr_isolate',
                    parameters={'host_ip': '{{incident.source_ip}}', 'isolation_type': 'network'}
                ),
                PlaybookAction(
                    id='collect_forensics',
                    name='Collect Forensic Data',
                    action_type='forensics_collection',
                    parameters={'host_ip': '{{incident.source_ip}}', 'data_types': ['memory', 'disk', 'network']},
                    depends_on=['isolate_host']
                ),
                PlaybookAction(
                    id='malware_analysis',
                    name='Submit to Malware Analysis',
                    action_type='malware_analysis',
                    parameters={'sample_source': 'forensics_data'},
                    depends_on=['collect_forensics']
                ),
                PlaybookAction(
                    id='update_iocs',
                    name='Update IOC Database',
                    action_type='ioc_update',
                    parameters={'source': 'malware_analysis_results'},
                    depends_on=['malware_analysis']
                )
            ]
        }

        # Phishing Response Playbook
        phishing_playbook = {
            'id': 'phishing_response',
            'name': 'Phishing Email Response',
            'description': 'Automated phishing email detection and remediation',
            'trigger_conditions': ['attack_type:phishing', 'severity:low,medium,high'],
            'actions': [
                PlaybookAction(
                    id='block_sender_domain',
                    name='Block Sender Domain',
                    action_type='email_block',
                    parameters={'domain': '{{incident.sender_domain}}', 'block_type': 'sender'}
                ),
                PlaybookAction(
                    id='quarantine_emails',
                    name='Quarantine Similar Emails',
                    action_type='email_quarantine',
                    parameters={'search_criteria': 'sender:{{incident.sender_domain}}'},
                    depends_on=['block_sender_domain']
                ),
                PlaybookAction(
                    id='user_notification',
                    name='Notify Affected Users',
                    action_type='user_notification',
                    parameters={'recipients': '{{incident.target_users}}', 'template': 'phishing_warning'},
                    depends_on=['quarantine_emails']
                )
            ]
        }

        self.playbooks = {
            'ddos_response': ddos_playbook,
            'malware_containment': malware_playbook,
            'phishing_response': phishing_playbook
        }

    def create_incident(self, incident_data: Dict[str, Any]) -> SecurityIncident:
        """Create a new security incident"""

        incident_id = f"INC-{str(uuid.uuid4())[:8]}"

        incident = SecurityIncident(
            id=incident_id,
            title=incident_data.get('title', 'Unknown Incident'),
            description=incident_data.get('description', ''),
            severity=IncidentSeverity(incident_data.get('severity', 'Medium')),
            source_ip=incident_data.get('source_ip', ''),
            target_ip=incident_data.get('target_ip', ''),
            attack_type=incident_data.get('attack_type', 'unknown')
        )

        self.incidents[incident_id] = incident
        self.logger.info(f"Created incident {incident_id}: {incident.title}")

        # Auto-assign playbook based on attack type and severity
        assigned_playbook = self.select_playbook(incident)
        if assigned_playbook:
            incident.assigned_playbook = assigned_playbook
            self.logger.info(f"Assigned playbook {assigned_playbook} to incident {incident_id}")

        return incident

    def select_playbook(self, incident: SecurityIncident) -> Optional[str]:
        """Select appropriate playbook based on incident characteristics"""

        attack_type = incident.attack_type.lower()
        severity = incident.severity.value.lower()

        # Simple playbook selection logic
        if 'ddos' in attack_type and severity in ['high', 'critical']:
            return 'ddos_response'
        elif 'malware' in attack_type and severity in ['medium', 'high', 'critical']:
            return 'malware_containment'
        elif 'phishing' in attack_type:
            return 'phishing_response'

        return None

    async def execute_playbook(self, incident_id: str, playbook_id: str = None) -> Dict[str, Any]:
        """Execute a playbook for a given incident"""

        if incident_id not in self.incidents:
            raise ValueError(f"Incident {incident_id} not found")

        incident = self.incidents[incident_id]

        if not playbook_id:
            playbook_id = incident.assigned_playbook

        if not playbook_id or playbook_id not in self.playbooks:
            raise ValueError(f"Playbook {playbook_id} not found")

        playbook = self.playbooks[playbook_id]
        execution_id = f"exec-{str(uuid.uuid4())[:8]}"

        execution_context = {
            'execution_id': execution_id,
            'incident_id': incident_id,
            'playbook_id': playbook_id,
            'status': PlaybookStatus.RUNNING,
            'started_at': datetime.now().isoformat(),
            'actions_completed': [],
            'actions_failed': [],
            'current_action': None,
            'variables': {'incident': asdict(incident)}
        }

        self.active_executions[execution_id] = execution_context
        self.logger.info(f"Started playbook execution {execution_id} for incident {incident_id}")

        try:
            # Execute playbook actions
            for action in playbook['actions']:
                # Check dependencies
                if not self.check_action_dependencies(action, execution_context):
                    self.logger.warning(f"Dependencies not met for action {action.id}")
                    continue

                execution_context['current_action'] = action.id
                self.logger.info(f"Executing action: {action.name}")

                # Execute the action
                result = await self.execute_action(action, execution_context)

                if result == ActionResult.SUCCESS:
                    execution_context['actions_completed'].append(action.id)
                    self.logger.info(f"Action {action.name} completed successfully")
                else:
                    execution_context['actions_failed'].append(action.id)
                    self.logger.error(f"Action {action.name} failed")

            # Determine final status
            if execution_context['actions_failed']:
                execution_context['status'] = PlaybookStatus.FAILED
            else:
                execution_context['status'] = PlaybookStatus.SUCCESS

        except Exception as e:
            self.logger.error(f"Playbook execution failed: {e}")
            execution_context['status'] = PlaybookStatus.FAILED

        finally:
            execution_context['completed_at'] = datetime.now().isoformat()
            execution_context['current_action'] = None

        return execution_context

    def check_action_dependencies(self, action: PlaybookAction, execution_context: Dict) -> bool:
        """Check if action dependencies are satisfied"""

        if not action.depends_on:
            return True

        completed_actions = execution_context.get('actions_completed', [])
        return all(dep in completed_actions for dep in action.depends_on)

    async def execute_action(self, action: PlaybookAction, context: Dict) -> ActionResult:
        """Execute a single playbook action"""

        try:
            # Simulate action execution based on type
            if action.action_type == 'firewall_block':
                return await self.execute_firewall_block(action, context)
            elif action.action_type == 'edr_isolate':
                return await self.execute_edr_isolate(action, context)
            elif action.action_type == 'email_block':
                return await self.execute_email_block(action, context)
            elif action.action_type == 'notification':
                return await self.execute_notification(action, context)
            else:
                # Generic action execution
                return await self.execute_generic_action(action, context)

        except Exception as e:
            self.logger.error(f"Action execution failed: {e}")
            return ActionResult.FAILED

    async def execute_firewall_block(self, action: PlaybookAction, context: Dict) -> ActionResult:
        """Execute firewall blocking action"""

        self.logger.info("Executing firewall block action...")

        # Simulate API call to firewall
        await asyncio.sleep(2)  # Simulate network delay

        # Mock successful execution
        ip_to_block = action.parameters.get('ip_list', '')
        self.logger.info(f"Blocked IP {ip_to_block} at firewall")

        return ActionResult.SUCCESS

    async def execute_edr_isolate(self, action: PlaybookAction, context: Dict) -> ActionResult:
        """Execute EDR host isolation action"""

        self.logger.info("Executing EDR host isolation...")

        # Simulate API call to EDR system
        await asyncio.sleep(3)  # Simulate network delay

        host_ip = action.parameters.get('host_ip', '')
        self.logger.info(f"Isolated host {host_ip} from network")

        return ActionResult.SUCCESS

    async def execute_email_block(self, action: PlaybookAction, context: Dict) -> ActionResult:
        """Execute email blocking action"""

        self.logger.info("Executing email block action...")

        # Simulate API call to email gateway
        await asyncio.sleep(1.5)

        domain = action.parameters.get('domain', '')
        self.logger.info(f"Blocked email domain {domain}")

        return ActionResult.SUCCESS

    async def execute_notification(self, action: PlaybookAction, context: Dict) -> ActionResult:
        """Execute notification action"""

        self.logger.info("Sending notification...")

        # Simulate notification sending
        await asyncio.sleep(1)

        channel = action.parameters.get('channel', 'email')
        message = action.parameters.get('message', 'Security incident detected')
        self.logger.info(f"Sent notification via {channel}: {message}")

        return ActionResult.SUCCESS

    async def execute_generic_action(self, action: PlaybookAction, context: Dict) -> ActionResult:
        """Execute generic action"""

        self.logger.info(f"Executing generic action: {action.name}")

        # Simulate action execution
        await asyncio.sleep(2)

        # 90% success rate for simulation
        import random
        if random.random() > 0.1:
            return ActionResult.SUCCESS
        else:
            return ActionResult.FAILED

    def get_incident_status(self, incident_id: str) -> Dict[str, Any]:
        """Get current status of an incident"""

        if incident_id not in self.incidents:
            return {'error': 'Incident not found'}

        incident = self.incidents[incident_id]

        # Find related executions
        related_executions = [
            exec_data for exec_data in self.active_executions.values()
            if exec_data['incident_id'] == incident_id
        ]

        return {
            'incident': asdict(incident),
            'executions': related_executions
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get SOAR engine performance metrics"""

        total_incidents = len(self.incidents)
        total_executions = len(self.active_executions)

        # Calculate success rates
        successful_executions = sum(
            1 for exec_data in self.active_executions.values()
            if exec_data['status'] == PlaybookStatus.SUCCESS
        )

        success_rate = successful_executions / total_executions if total_executions > 0 else 0

        # Calculate average response time
        completed_executions = [
            exec_data for exec_data in self.active_executions.values()
            if 'completed_at' in exec_data
        ]

        avg_response_time = 0
        if completed_executions:
            total_time = 0
            for exec_data in completed_executions:
                start_time = datetime.fromisoformat(exec_data['started_at'])
                end_time = datetime.fromisoformat(exec_data['completed_at'])
                total_time += (end_time - start_time).total_seconds()
            avg_response_time = total_time / len(completed_executions)

        return {
            'total_incidents': total_incidents,
            'total_executions': total_executions,
            'successful_executions': successful_executions,
            'success_rate': round(success_rate * 100, 2),
            'average_response_time': round(avg_response_time, 2),
            'active_playbooks': len(self.playbooks)
        }

# Example usage
if __name__ == "__main__":
    async def main():
        soar = SOAREngine()

        print("=== CyberSentinel AI SOAR Engine ===\n")

        # Create sample incidents
        ddos_incident = soar.create_incident({
            'title': 'DDoS Attack Detected',
            'description': 'High volume traffic from multiple sources',
            'severity': 'High',
            'source_ip': '185.220.101.42',
            'target_ip': '192.168.1.100',
            'attack_type': 'ddos'
        })

        malware_incident = soar.create_incident({
            'title': 'Malware Communication Detected',
            'description': 'Suspicious outbound connection to known C2 server',
            'severity': 'Critical',
            'source_ip': '192.168.1.105',
            'target_ip': 'external-c2.malware.net',
            'attack_type': 'malware'
        })

        print(f"Created incidents: {ddos_incident.id}, {malware_incident.id}")

        # Execute playbooks
        print("\nExecuting playbooks...")

        ddos_execution = await soar.execute_playbook(ddos_incident.id)
        malware_execution = await soar.execute_playbook(malware_incident.id)

        print(f"DDoS playbook execution: {ddos_execution['status'].value}")
        print(f"Malware playbook execution: {malware_execution['status'].value}")

        # Show metrics
        metrics = soar.get_metrics()
        print("\n=== SOAR Engine Metrics ===")
        print(f"Total Incidents: {metrics['total_incidents']}")
        print(f"Total Executions: {metrics['total_executions']}")
        print(f"Success Rate: {metrics['success_rate']}%")
        print(f"Average Response Time: {metrics['average_response_time']} seconds")

    # Run the async main function
    asyncio.run(main())

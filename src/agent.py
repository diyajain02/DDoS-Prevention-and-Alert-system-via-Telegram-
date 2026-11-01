"""Lightweight agent architecture for Light-SOC.
Agents run on endpoints and send data to a central manager."""
import json
import logging
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import queue

from src.config_loader import get_config
from src.models import LogEntry


logger = logging.getLogger(__name__)


class AgentStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    DISCONNECTED = "disconnected"
    REMOVED = "removed"


class MessageType(str, Enum):
    HEARTBEAT = "heartbeat"
    LOG_ENTRIES = "log_entries"
    FIM_ALERTS = "fim_alerts"
    VULN_ALERTS = "vuln_alerts"
    SCA_ALERTS = "sca_alerts"
    COMMAND = "command"
    COMMAND_RESULT = "command_result"
    REGISTER = "register"
    REGISTER_RESPONSE = "register_response"
    CONFIG_UPDATE = "config_update"


@dataclass
class AgentInfo:
    """Information about a registered agent."""
    agent_id: str
    name: str
    ip: str
    platform: str
    version: str
    status: AgentStatus = AgentStatus.PENDING
    registered_at: datetime = field(default_factory=datetime.now)
    last_heartbeat: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    config_version: int = 0


@dataclass
class AgentMessage:
    """Message exchanged between agent and manager."""
    message_type: MessageType
    agent_id: str
    payload: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_json(self) -> str:
        return json.dumps({
            'message_type': self.message_type.value,
            'agent_id': self.agent_id,
            'payload': self.payload,
            'timestamp': self.timestamp.isoformat(),
            'message_id': self.message_id,
        })

    @classmethod
    def from_json(cls, data: str) -> 'AgentMessage':
        obj = json.loads(data)
        return cls(
            message_type=MessageType(obj['message_type']),
            agent_id=obj['agent_id'],
            payload=obj['payload'],
            timestamp=datetime.fromisoformat(obj['timestamp']),
            message_id=obj['message_id'],
        )


class Agent:
    """Light-SOC Agent - runs on endpoints."""

    def __init__(self, manager_host: str, manager_port: int = 8443, use_ssl: bool = True):
        self.config = get_config()
        self.manager_host = manager_host
        self.manager_port = manager_port
        self.use_ssl = use_ssl
        
        # Generate or load agent ID
        self.agent_id = self._get_or_create_agent_id()
        self.name = socket.gethostname()
        self.platform = self._get_platform()
        self.version = "0.1.0"
        
        self.socket: Optional[ssl.SSLSocket] = None
        self.running = False
        self.send_thread: Optional[threading.Thread] = None
        self.recv_thread: Optional[threading.Thread] = None
        self.heartbeat_thread: Optional[threading.Thread] = None
        
        self.outbound_queue: queue.Queue = queue.Queue()
        self.inbound_handlers: Dict[MessageType, Callable] = {}
        self.lock = threading.RLock()
        
        # Register default handlers
        self.inbound_handlers[MessageType.COMMAND] = self._handle_command
        self.inbound_handlers[MessageType.CONFIG_UPDATE] = self._handle_config_update
        self.inbound_handlers[MessageType.REGISTER_RESPONSE] = self._handle_register_response

    def _get_or_create_agent_id(self) -> str:
        """Get existing agent ID or create new one."""
        id_file = Path(self.config['general']['data_dir']) / 'agent_id'
        if id_file.exists():
            try:
                return id_file.read_text().strip()
            except Exception:
                pass
        
        agent_id = str(uuid.uuid4())
        id_file.parent.mkdir(parents=True, exist_ok=True)
        id_file.write_text(agent_id)
        return agent_id

    def _get_platform(self) -> str:
        """Get platform identifier."""
        import platform
        return f"{platform.system()}-{platform.machine()}"

    def connect(self) -> bool:
        """Connect to the manager."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # In production, use proper certs
                self.socket = context.wrap_socket(sock, server_hostname=self.manager_host)
            else:
                self.socket = sock
            
            self.socket.connect((self.manager_host, self.manager_port))
            logger.info(f"Agent {self.agent_id} connected to manager {self.manager_host}:{self.manager_port}")
            
            # Send registration
            self._send_register()
            
            return True
        except Exception as e:
            logger.error(f"Agent connection failed: {e}")
            return False

    def disconnect(self):
        """Disconnect from manager."""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None
        logger.info(f"Agent {self.agent_id} disconnected")

    def start(self):
        """Start agent threads."""
        if not self.connect():
            return False
        
        self.running = True
        
        self.send_thread = threading.Thread(target=self._send_loop, daemon=True)
        self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        
        self.send_thread.start()
        self.recv_thread.start()
        self.heartbeat_thread.start()
        
        logger.info(f"Agent {self.agent_id} started")
        return True

    def stop(self):
        """Stop agent."""
        self.running = False
        self.disconnect()
        
        for t in [self.send_thread, self.recv_thread, self.heartbeat_thread]:
            if t:
                t.join(timeout=5)
        
        logger.info(f"Agent {self.agent_id} stopped")

    def _send_register(self):
        """Send registration message."""
        msg = AgentMessage(
            message_type=MessageType.REGISTER,
            agent_id=self.agent_id,
            payload={
                'name': self.name,
                'platform': self.platform,
                'version': self.version,
                'ip': self._get_local_ip(),
            }
        )
        self.outbound_queue.put(msg)

    def _handle_register_response(self, msg: AgentMessage):
        """Handle registration response."""
        if msg.payload.get('accepted'):
            logger.info(f"Agent {self.agent_id} registered successfully")
        else:
            logger.error(f"Agent registration rejected: {msg.payload.get('reason')}")

    def _handle_command(self, msg: AgentMessage):
        """Handle command from manager."""
        command = msg.payload.get('command')
        args = msg.payload.get('args', {})
        
        logger.info(f"Agent received command: {command}")
        
        # Execute command (limited set for security)
        result = self._execute_command(command, args)
        
        # Send result back
        response = AgentMessage(
            message_type=MessageType.COMMAND_RESULT,
            agent_id=self.agent_id,
            payload={
                'command': command,
                'result': result,
                'request_id': msg.message_id,
            }
        )
        self.outbound_queue.put(response)

    def _handle_config_update(self, msg: AgentMessage):
        """Handle configuration update from manager."""
        config = msg.payload.get('config', {})
        logger.info(f"Agent received config update: {config}")
        # Apply config updates
        # This would update local configuration files

    def _execute_command(self, command: str, args: Dict) -> Dict:
        """Execute a command from the manager."""
        allowed_commands = {
            'fim_scan': self._cmd_fim_scan,
            'vuln_scan': self._cmd_vuln_scan,
            'sca_scan': self._cmd_sca_scan,
            'collect_logs': self._cmd_collect_logs,
            'block_ip': self._cmd_block_ip,
            'unblock_ip': self._cmd_unblock_ip,
            'get_status': self._cmd_get_status,
            'restart': self._cmd_restart,
        }
        
        if command not in allowed_commands:
            return {'success': False, 'error': f'Command not allowed: {command}'}
        
        try:
            return allowed_commands[command](args)
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _cmd_fim_scan(self, args: Dict) -> Dict:
        from src.fim import get_fim_monitor
        fim = get_fim_monitor()
        fim.scan()
        alerts = fim.get_alerts()
        return {'success': True, 'alerts_count': len(alerts)}

    def _cmd_vuln_scan(self, args: Dict) -> Dict:
        from src.vulnerability_detector import get_vuln_detector
        vuln = get_vuln_detector()
        result = vuln.scan()
        return {'success': True, 'vulnerable_packages': result.vulnerable_packages, 'total_cves': result.total_cves}

    def _cmd_sca_scan(self, args: Dict) -> Dict:
        from src.sca import get_sca_scanner
        sca = get_sca_scanner()
        result = sca.scan()
        return {'success': True, 'passed': result.passed, 'failed': result.failed}

    def _cmd_collect_logs(self, args: Dict) -> Dict:
        lines = args.get('lines', 100)
        log_path = args.get('path', '/var/log/auth.log')
        try:
            result = subprocess.run(['tail', '-n', str(lines), log_path], capture_output=True, text=True)
            return {'success': True, 'logs': result.stdout}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _cmd_block_ip(self, args: Dict) -> Dict:
        from src.blocker import get_blocker
        blocker = get_blocker()
        ip = args.get('ip')
        reason = args.get('reason', 'Agent command')
        duration = args.get('duration', 3600)
        success = blocker.block_ip(ip, reason, duration)
        return {'success': success}

    def _cmd_unblock_ip(self, args: Dict) -> Dict:
        from src.blocker import get_blocker
        blocker = get_blocker()
        ip = args.get('ip')
        success = blocker.unblock_ip(ip)
        return {'success': success}

    def _cmd_get_status(self, args: Dict) -> Dict:
        return {
            'success': True,
            'agent_id': self.agent_id,
            'name': self.name,
            'platform': self.platform,
            'version': self.version,
            'uptime': time.time(),  # Would track actual uptime
        }

    def _cmd_restart(self, args: Dict) -> Dict:
        # Signal restart
        threading.Thread(target=self._delayed_restart, daemon=True).start()
        return {'success': True, 'message': 'Restarting...'}

    def _delayed_restart(self):
        time.sleep(1)
        self.stop()
        # In a real deployment, this would be handled by systemd/process manager

    def _send_loop(self):
        """Send messages from queue."""
        while self.running and self.socket:
            try:
                msg = self.outbound_queue.get(timeout=1)
                self._send_message(msg)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Send loop error: {e}")
                break

    def _recv_loop(self):
        """Receive and process messages."""
        buffer = ""
        while self.running and self.socket:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                buffer += data
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        try:
                            msg = AgentMessage.from_json(line)
                            handler = self.inbound_handlers.get(msg.message_type)
                            if handler:
                                handler(msg)
                            else:
                                logger.warning(f"No handler for message type: {msg.message_type}")
                        except Exception as e:
                            logger.error(f"Failed to process message: {e}")
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Receive loop error: {e}")
                break
        
        logger.info("Connection lost, attempting reconnect...")
        self._reconnect()

    def _reconnect(self):
        """Attempt to reconnect to manager."""
        while self.running:
            time.sleep(10)
            if self.connect():
                break

    def _heartbeat_loop(self):
        """Send periodic heartbeats."""
        while self.running:
            time.sleep(30)  # Heartbeat every 30 seconds
            if self.running:
                msg = AgentMessage(
                    message_type=MessageType.HEARTBEAT,
                    agent_id=self.agent_id,
                    payload={'status': 'alive', 'timestamp': datetime.now().isoformat()}
                )
                self.outbound_queue.put(msg)

    def _send_message(self, msg: AgentMessage):
        """Send a message over the socket."""
        if self.socket:
            try:
                self.socket.sendall((msg.to_json() + '\n').encode('utf-8'))
            except Exception as e:
                logger.error(f"Failed to send message: {e}")

    def send_log_entries(self, entries: List[LogEntry]):
        """Send log entries to manager."""
        msg = AgentMessage(
            message_type=MessageType.LOG_ENTRIES,
            agent_id=self.agent_id,
            payload={'entries': [e.to_dict() for e in entries]}
        )
        self.outbound_queue.put(msg)

    def send_fim_alerts(self, alerts: List):
        """Send FIM alerts to manager."""
        msg = AgentMessage(
            message_type=MessageType.FIM_ALERTS,
            agent_id=self.agent_id,
            payload={'alerts': [a.to_log_entry().to_dict() for a in alerts]}
        )
        self.outbound_queue.put(msg)

    def send_vuln_alerts(self, alerts: List[LogEntry]):
        """Send vulnerability alerts to manager."""
        msg = AgentMessage(
            message_type=MessageType.VULN_ALERTS,
            agent_id=self.agent_id,
            payload={'alerts': [a.to_dict() for a in alerts]}
        )
        self.outbound_queue.put(msg)

    def send_sca_alerts(self, alerts: List[LogEntry]):
        """Send SCA alerts to manager."""
        msg = AgentMessage(
            message_type=MessageType.SCA_ALERTS,
            agent_id=self.agent_id,
            payload={'alerts': [a.to_dict() for a in alerts]}
        )
        self.outbound_queue.put(msg)

    def _get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"


class AgentManager:
    """Central manager for Light-SOC agents."""

    def __init__(self, host: str = '0.0.0.0', port: int = 8443):
        self.config = get_config()
        self.host = host
        self.port = port
        
        self.agents: Dict[str, AgentInfo] = {}
        self.agent_connections: Dict[str, ssl.SSLSocket] = {}
        self.message_queue: queue.Queue = queue.Queue()
        
        self.server_socket: Optional[socket.socket] = None
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.running = False
        self.accept_thread: Optional[threading.Thread] = None
        self.process_thread: Optional[threading.Thread] = None
        
        self.lock = threading.RLock()
        self._setup_ssl()

    def _setup_ssl(self):
        """Setup SSL context for secure communication."""
        cert_path = Path(self.config['general']['data_dir']) / 'certs' / 'server.pem'
        key_path = Path(self.config['general']['data_dir']) / 'certs' / 'server.key'
        
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate self-signed cert if not exists (for development)
        if not cert_path.exists() or not key_path.exists():
            self._generate_self_signed_cert(cert_path, key_path)
        
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(cert_path, key_path)

    def _generate_self_signed_cert(self, cert_path: Path, key_path: Path):
        """Generate self-signed certificate for development."""
        import subprocess
        try:
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', str(key_path), '-out', str(cert_path),
                '-days', '365', '-nodes', '-subj', '/CN=light-soc-manager'
            ], check=True, capture_output=True)
            logger.info("Generated self-signed certificate for manager")
        except Exception as e:
            logger.error(f"Failed to generate certificate: {e}")

    def start(self):
        """Start the manager server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(50)
        
        self.running = True
        self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.process_thread = threading.Thread(target=self._process_loop, daemon=True)
        
        self.accept_thread.start()
        self.process_thread.start()
        
        logger.info(f"Agent Manager started on {self.host}:{self.port}")

    def stop(self):
        """Stop the manager."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.accept_thread:
            self.accept_thread.join(timeout=5)
        if self.process_thread:
            self.process_thread.join(timeout=5)
        logger.info("Agent Manager stopped")

    def _accept_loop(self):
        """Accept incoming agent connections."""
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                client_sock.settimeout(30)
                
                # Wrap with SSL
                try:
                    ssl_sock = self.ssl_context.wrap_socket(client_sock, server_side=True)
                except Exception as e:
                    logger.warning(f"SSL handshake failed from {addr}: {e}")
                    client_sock.close()
                    continue
                
                logger.info(f"New connection from {addr}")
                threading.Thread(target=self._handle_agent_connection, args=(ssl_sock, addr), daemon=True).start()
                
            except Exception as e:
                if self.running:
                    logger.error(f"Accept error: {e}")

    def _handle_agent_connection(self, ssl_sock: ssl.SSLSocket, addr: tuple):
        """Handle messages from a connected agent."""
        buffer = ""
        agent_id = None
        
        try:
            while self.running:
                data = ssl_sock.recv(4096).decode('utf-8')
                if not data:
                    break
                
                buffer += data
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        try:
                            msg = AgentMessage.from_json(line)
                            
                            if not agent_id:
                                agent_id = msg.agent_id
                                with self.lock:
                                    self.agent_connections[agent_id] = ssl_sock
                            
                            self.message_queue.put((agent_id, msg))
                            
                        except Exception as e:
                            logger.error(f"Failed to parse message from {addr}: {e}")
        except Exception as e:
            logger.error(f"Agent connection error: {e}")
        finally:
            if agent_id:
                with self.lock:
                    self.agent_connections.pop(agent_id, None)
                    if agent_id in self.agents:
                        self.agents[agent_id].status = AgentStatus.DISCONNECTED
            ssl_sock.close()
            logger.info(f"Agent {agent_id or addr} disconnected")

    def _process_loop(self):
        """Process queued messages."""
        while self.running:
            try:
                agent_id, msg = self.message_queue.get(timeout=1)
                self._process_message(agent_id, msg)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Process loop error: {e}")

    def _process_message(self, agent_id: str, msg: AgentMessage):
        """Process a message from an agent."""
        if msg.message_type == MessageType.REGISTER:
            self._handle_register(agent_id, msg)
        elif msg.message_type == MessageType.HEARTBEAT:
            self._handle_heartbeat(agent_id, msg)
        elif msg.message_type == MessageType.LOG_ENTRIES:
            self._handle_log_entries(agent_id, msg)
        elif msg.message_type == MessageType.FIM_ALERTS:
            self._handle_fim_alerts(agent_id, msg)
        elif msg.message_type == MessageType.VULN_ALERTS:
            self._handle_vuln_alerts(agent_id, msg)
        elif msg.message_type == MessageType.SCA_ALERTS:
            self._handle_sca_alerts(agent_id, msg)
        elif msg.message_type == MessageType.COMMAND_RESULT:
            self._handle_command_result(agent_id, msg)

    def _handle_register(self, agent_id: str, msg: AgentMessage):
        """Handle agent registration."""
        payload = msg.payload
        
        with self.lock:
            if agent_id in self.agents:
                # Existing agent reconnecting
                agent = self.agents[agent_id]
                agent.status = AgentStatus.ACTIVE
                agent.last_heartbeat = datetime.now()
                agent.ip = payload.get('ip', agent.ip)
            else:
                # New agent
                agent = AgentInfo(
                    agent_id=agent_id,
                    name=payload.get('name', 'unknown'),
                    ip=payload.get('ip', 'unknown'),
                    platform=payload.get('platform', 'unknown'),
                    version=payload.get('version', 'unknown'),
                    status=AgentStatus.ACTIVE,
                )
                self.agents[agent_id] = agent
            
            logger.info(f"Agent registered: {agent.name} ({agent_id}) from {agent.ip}")
        
        # Send registration response
        self._send_to_agent(agent_id, AgentMessage(
            message_type=MessageType.REGISTER_RESPONSE,
            agent_id=agent_id,
            payload={'accepted': True, 'config_version': 0}
        ))

    def _handle_heartbeat(self, agent_id: str, msg: AgentMessage):
        """Handle agent heartbeat."""
        with self.lock:
            if agent_id in self.agents:
                self.agents[agent_id].last_heartbeat = datetime.now()
                self.agents[agent_id].status = AgentStatus.ACTIVE

    def _handle_log_entries(self, agent_id: str, msg: AgentMessage):
        """Process log entries from agent."""
        entries_data = msg.payload.get('entries', [])
        for entry_data in entries_data:
            entry = LogEntry(
                timestamp=datetime.fromisoformat(entry_data['timestamp']),
                raw_line=entry_data['raw_line'],
                source_ip=entry_data.get('source_ip'),
                username=entry_data.get('username'),
                event_type=entry_data.get('event_type'),
                details=entry_data.get('details', {}),
            )
            # Process through detection engine
            from src.detection_engine import DetectionEngine
            engine = DetectionEngine()
            engine.process_entry(entry)

    def _handle_fim_alerts(self, agent_id: str, msg: AgentMessage):
        """Process FIM alerts from agent."""
        alerts_data = msg.payload.get('alerts', [])
        for alert_data in alerts_data:
            entry = LogEntry(
                timestamp=datetime.fromisoformat(alert_data['timestamp']),
                raw_line=alert_data['raw_line'],
                source_ip=alert_data.get('source_ip'),
                username=alert_data.get('username'),
                event_type=alert_data.get('event_type'),
                details=alert_data.get('details', {}),
            )
            # Process through detection engine
            from src.detection_engine import DetectionEngine
            engine = DetectionEngine()
            engine.process_entry(entry)

    def _handle_vuln_alerts(self, agent_id: str, msg: AgentMessage):
        """Process vulnerability alerts from agent."""
        alerts_data = msg.payload.get('alerts', [])
        for alert_data in alerts_data:
            entry = LogEntry(
                timestamp=datetime.fromisoformat(alert_data['timestamp']),
                raw_line=alert_data['raw_line'],
                source_ip=alert_data.get('source_ip'),
                username=alert_data.get('username'),
                event_type=alert_data.get('event_type'),
                details=alert_data.get('details', {}),
            )
            from src.detection_engine import DetectionEngine
            engine = DetectionEngine()
            engine.process_entry(entry)

    def _handle_sca_alerts(self, agent_id: str, msg: AgentMessage):
        """Process SCA alerts from agent."""
        alerts_data = msg.payload.get('alerts', [])
        for alert_data in alerts_data:
            entry = LogEntry(
                timestamp=datetime.fromisoformat(alert_data['timestamp']),
                raw_line=alert_data['raw_line'],
                source_ip=alert_data.get('source_ip'),
                username=alert_data.get('username'),
                event_type=alert_data.get('event_type'),
                details=alert_data.get('details', {}),
            )
            from src.detection_engine import DetectionEngine
            engine = DetectionEngine()
            engine.process_entry(entry)

    def _handle_command_result(self, agent_id: str, msg: AgentMessage):
        """Handle command result from agent."""
        logger.info(f"Command result from {agent_id}: {msg.payload}")

    def _send_to_agent(self, agent_id: str, msg: AgentMessage):
        """Send a message to a specific agent."""
        with self.lock:
            sock = self.agent_connections.get(agent_id)
        
        if sock:
            try:
                sock.sendall((msg.to_json() + '\n').encode('utf-8'))
            except Exception as e:
                logger.error(f"Failed to send to agent {agent_id}: {e}")

    def send_command(self, agent_id: str, command: str, args: Dict = None) -> bool:
        """Send a command to an agent."""
        msg = AgentMessage(
            message_type=MessageType.COMMAND,
            agent_id=agent_id,
            payload={'command': command, 'args': args or {}}
        )
        return self._send_to_agent(agent_id, msg) is not None

    def broadcast_command(self, command: str, args: Dict = None, agent_filter: Callable[[AgentInfo], bool] = None):
        """Send command to multiple agents."""
        with self.lock:
            agents = list(self.agents.values())
        
        for agent in agents:
            if agent.status == AgentStatus.ACTIVE:
                if agent_filter is None or agent_filter(agent):
                    self.send_command(agent.agent_id, command, args)

    def get_agents(self) -> List[AgentInfo]:
        """Get all registered agents."""
        with self.lock:
            return list(self.agents.values())

    def get_agent(self, agent_id: str) -> Optional[AgentInfo]:
        """Get agent by ID."""
        with self.lock:
            return self.agents.get(agent_id)

    def remove_agent(self, agent_id: str) -> bool:
        """Remove an agent."""
        with self.lock:
            if agent_id in self.agents:
                self.agents[agent_id].status = AgentStatus.REMOVED
                del self.agents[agent_id]
            if agent_id in self.agent_connections:
                try:
                    self.agent_connections[agent_id].close()
                except Exception:
                    pass
                del self.agent_connections[agent_id]
                return True
        return False


def get_agent_manager() -> AgentManager:
    """Get singleton agent manager instance."""
    if not hasattr(get_agent_manager, '_instance'):
        get_agent_manager._instance = AgentManager()
    return get_agent_manager._instance
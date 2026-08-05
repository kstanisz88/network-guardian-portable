#!/usr/bin/env python3
"""
Task 4: Alert Manager - Telegram + Windows Toast notifications
Task 5: Response Advisor - Rule-based remediation steps per threat type
"""

import requests
import json
import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class AlertLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Alert data structure."""
    level: AlertLevel
    title: str
    message: str
    threat_type: str
    threat_category: str
    confidence: float
    flow_info: Dict[str, Any]
    timestamp: datetime
    remediation_steps: List[str]


class TelegramAlertManager:
    """Manages Telegram Bot API alerts."""
    
    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        parse_mode: str = "HTML",
        disable_web_page_preview: bool = True,
        timeout: int = 10
    ):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.parse_mode = parse_mode
        self.disable_web_page_preview = disable_web_page_preview
        self.timeout = timeout
        self.api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        self._last_alert_time = 0
        self._cooldown = 30  # seconds
    
    def set_cooldown(self, seconds: int):
        """Set minimum time between alerts."""
        self._cooldown = max(0, seconds)
    
    def _check_cooldown(self) -> bool:
        """Check if cooldown period has passed."""
        now = time.time()
        if now - self._last_alert_time < self._cooldown:
            return False
        self._last_alert_time = now
        return True
    
    def send(self, alert: Alert) -> bool:
        """Send alert via Telegram."""
        if not self._check_cooldown():
            logger.debug("Alert skipped due to cooldown")
            return False
        
        message = self.format_alert(alert)
        try:
            resp = requests.post(
                self.api_url,
                json={
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": self.parse_mode,
                    "disable_web_page_preview": self.disable_web_page_preview
                },
                timeout=self.timeout
            )
            if resp.status_code == 200:
                logger.info(f"✅ Telegram alert sent: {alert.threat_type}")
                return True
            else:
                logger.error(f"Telegram API error: {resp.status_code} - {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
            return False
    
    def format_alert(self, alert: Alert) -> str:
        """Format alert for Telegram (HTML)."""
        level_icons = {
            AlertLevel.INFO: "ℹ️",
            AlertLevel.WARNING: "⚠️",
            AlertLevel.CRITICAL: "🚨"
        }
        icon = level_icons.get(alert.level, "🔔")
        
        # Threat category emoji
        cat_emoji = {
            'dos': '💥', 'probe': '🔍', 'r2l': '🔓', 'u2r': '⬆️',
            'normal': '✅', 'unknown': '❓'
        }
        cat_icon = cat_emoji.get(alert.threat_category, '⚠️')
        
        lines = [
            f"{icon} <b>NETWORK GUARDIAN ALERT</b> {icon}",
            f"",
            f"{cat_icon} <b>Kategoria:</b> {alert.threat_category.upper()}",
            f"🎯 <b>Typ ataku:</b> {alert.threat_type}",
            f"📊 <b>Pewność:</b> {alert.confidence:.1%}",
            f"📈 <b>Poziom:</b> {alert.level.value.upper()}",
            f"🕐 <b>Czas:</b> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"",
            f"📡 <b>Szczegóły przepływu:</b>",
        ]
        
        flow = alert.flow_info
        if flow.get('src_ip'):
            lines.append(f"  • Źródło: <code>{flow['src_ip']}</code>:<code>{flow.get('src_port', 'N/A')}</code>")
        if flow.get('dst_ip'):
            lines.append(f"  • Cel: <code>{flow['dst_ip']}</code>:<code>{flow.get('dst_port', 'N/A')}</code>")
        if flow.get('protocol'):
            lines.append(f"  • Protokół: <b>{flow['protocol']}</b>")
        if flow.get('bytes_total'):
            lines.append(f"  • Dane: {self._format_bytes(flow['bytes_total'])}")
        if flow.get('packets_total'):
            lines.append(f"  • Pakiety: {flow['packets_total']}")
        if flow.get('duration_ms'):
            lines.append(f"  • Czas trwania: {flow['duration_ms']} ms")
        
        if alert.remediation_steps:
            lines.append(f"")
            lines.append(f"🛠 <b>Zalecane działania:</b>")
            for i, step in enumerate(alert.remediation_steps[:5], 1):
                lines.append(f"  {i}. {step}")
            if len(alert.remediation_steps) > 5:
                lines.append(f"  ... i {len(alert.remediation_steps) - 5} więcej")
        
        return "\n".join(lines)
    
    @staticmethod
    def _format_bytes(bytes_val: int) -> str:
        """Format bytes to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} TB"
    
    def test_connection(self) -> bool:
        """Test Telegram bot connection."""
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/getMe"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                logger.info(f"✅ Telegram bot connected: @{data['result']['username']}")
                return True
        except Exception as e:
            logger.error(f"Telegram connection test failed: {e}")
        return False


class WindowsToastNotifier:
    """Windows 10/11 toast notifications."""
    
    def __init__(self, app_name: str = "Network Guardian", enabled: bool = True):
        self.app_name = app_name
        self.enabled = enabled
        self._toaster = None
        if enabled:
            self._init_toaster()
    
    def _init_toaster(self):
        """Initialize win10toast."""
        try:
            from win10toast import ToastNotifier
            self._toaster = ToastNotifier()
        except ImportError:
            logger.warning("win10toast not available, toast notifications disabled")
            self.enabled = False
        except Exception as e:
            logger.warning(f"Toast notifier init failed: {e}")
            self.enabled = False
    
    def notify(self, title: str, message: str, duration: int = 10) -> bool:
        """Show toast notification."""
        if not self.enabled or not self._toaster:
            return False
        try:
            self._toaster.show_toast(
                title=title,
                msg=message,
                duration=duration,
                threaded=True
            )
            return True
        except Exception as e:
            logger.error(f"Toast notification failed: {e}")
            return False


class ResponseAdvisor:
    """
    Rule-based remediation advisor.
    Provides specific next steps based on threat type and category.
    """
    
    REMEDIATION_DB = {
        # DoS Attacks
        'dos': {
            'title': 'Atak typu Denial of Service (DoS)',
            'steps': [
                "Zidentyfikuj IP źródłowe ataku z alertu",
                "Zablokuj IP na firewallu (Windows Defender / firewall sprzętowy / router)",
                "Sprawdź czy serwer docelowy nadal odpowiada (ping, sprawdź usługi)",
                "Włącz limitowanie połączeń (rate limiting) na docelowym porcie",
                "Rozważ włączenie DDoS protection (Cloudflare, AWS Shield, itp.)",
                "Przeanalizuj logi serwera pod kątem wzorca ataku (SYN flood, UDP flood, itp.)",
                "Jeśli to atak rozproszony (DDoS) - skontaktuj się z ISP / providerem hostingowym",
            ]
        },
        
        # Probe/Scanning
        'probe': {
            'title': 'Skanowanie / Rekonesans (Probe/Scan)',
            'steps': [
                "Zidentyfikuj IP skanującego z alertu",
                "Zablokuj IP na firewallu (tymczasowo lub permanentnie)",
                "Sprawdź czy skanowanie dotknęło otwartych portów/usług",
                "Zamknij niepotrzebne porty na firewallu (tylko te wymagane)",
                "Włącz fail2ban / port knocking / port knocking dla usług krytycznych",
                "Sprawdź logi systemowe (Event Viewer → Security) pod kątem prób logowania",
                "Rozważ implementację port knocking lub Single Packet Authorization (SPA)",
            ]
        },
        
        # Remote to Local
        'r2l': {
            'title': 'Próba zdalnego dostępu / atak na uwierzytelnianie (R2L)',
            'steps': [
                "Zablokuj IP atakującego na firewallu",
                "Sprawdź czy próba logowania się udała (Event ID 4624 - sukces, 4625 - porażka)",
                "Wymuś zmianę haseł na wszystkich kontach, które mogły zostać zaatakowane",
                "Włącz wieloskładnikowe uwierzytelnianie (MFA/2FA) na wszystkich usługach zdalnych",
                "Sprawdź czy nie utworzono nowych kont / kluczy SSH / certyfikatów",
                "Przeglądaj logi uwierzytelniania (SSH, RDP, VPN, Web) pod kątem anomalii",
                "Rozważ wdrożenie Zero Trust / Conditional Access",
            ]
        },
        
        # User to Root
        'u2r': {
            'title': 'Eskalacja uprawnień / Exploit lokalny (U2R)',
            'steps': [
                "NATYCHMIAST izoluj hosta od sieci (odłącz kabel / wyłącz Wi-Fi / VLAN quarantine)",
                "Zrób zrzut pamięci (memory dump) do analizy forensics (Volatility, WinDbg)",
                "Sprawdź procesy uruchomione z uprawnieniami SYSTEM/Administrator (Process Hacker, Sysinternals)",
                "Przeskanuj system EDR/AV w trybie offline (Windows Defender Offline, Kaspersky Rescue Disk)",
                "Sprawdź mechanizmy persistence: Run keys, Services, Scheduled Tasks, WMI, Startup",
                "Przeanalizuj logi Event Viewer (System, Security, Application) pod kątem błędów/escalacji",
                "Jeśli potwierdzone - reimage hosta / przywróć z czystego backupu",
            ]
        },
        
        # Data Exfiltration
        'data_exfiltration': {
            'title': 'Eksfiltracja danych / nietypowy ruch wychodzący',
            'steps': [
                "Zablokuj połączenie wychodzące do docelowego IP/domeny na firewallu",
                "Zidentyfikuj proces wysyłający dane (Resource Monitor → Network / Process Hacker / netstat -ano)",
                "Sprawdź czy to legitymine: backup, aktualizacja, cloud sync, telemetria",
                "Jeśli nielegitymine - zrób zrzut pamięci procesu, zbieraj logi sieciowe (PCAP)",
                "Sprawdź DLP / proxy / firewall logi pod kątem objętości i celu transferu",
                "Zidentyfikuj jakie pliki/dane mogły zostać skradzione",
                "Powiadom DPO / zespół bezpieczeństwa / zarządzanie (RODO: 72h na zgłoszenie)",
            ]
        },
        
        # Malware C2
        'malware_c2': {
            'title': 'Komunikacja z C2 (Command & Control) / malware beaconing',
            'steps': [
                "Zablokuj domenę/IP C2 na firewallu i DNS (sinkhole)",
                "Zeskanuj hosta EDR/AV (pełne skanowanie offline)",
                "Sprawdź persistence: Run keys, Services, Scheduled Tasks, WMI, COM hijacking",
                "Przeanalizuj ruch sieciowy: beaconing interval, domain generation algorithm (DGA)",
                "Sprawdź czy inne hosty w sieci komunikują się z tym samym C2",
                "Izoluuj hosta od sieci korporacyjnej (quarantine VLAN)",
                "Rozpocznij procedurę Incident Response (IR)",
            ]
        },
        
        # Generic anomaly
        'anomaly': {
            'title': 'Wykryto anomalię w ruchu sieciowym',
            'steps': [
                "Sprawdź czy to fałszywy alarm: nowa aplikacja, backup, aktualizacja systemu, skan AV",
                "Porównaj z baseline'em normalnego ruchu tego hosta/użytkownika",
                "Sprawdź kontekst: godzina, użytkownik, aplikacja, cel połączenia",
                "Jeśli podejrzane - eskaluj do zespołu SOC / administratora sieci",
                "Jeśli legitymine - dodaj do whitelist / wykluczeń w konfiguracji",
                "Monitoruj ten host przez najbliższe 24h pod kątem powtórzeń",
            ]
        },
        
        # Phishing (from phishing-detector model)
        'phishing': {
            'title': 'Wykryto podejrzany URL / phishing',
            'steps': [
                "NIE KLIKAJ w link / nie otwieraj załącznika",
                "Zgłoś wiadomość do zespołu IT/Security (phish@firma.pl)",
                "Sprawdź czy inni pracownicy otrzymali podobną wiadomość",
                "Zablokuj domenę na proxy/DNS/firewall",
                "Przeprowadź szkolenie phishing awareness dla zespołu",
                "Sprawdź czy ktoś wkleił dane logowania na fałszywej stronie - jeśli tak, zmień hasło natychmiast",
            ]
        },
    }
    
    # Specific threat type overrides
    THREAT_SPECIFIC = {
        'neptune': 'dos', 'smurf': 'dos', 'back': 'dos', 'land': 'dos', 'pod': 'dos', 'teardrop': 'dos',
        'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 'satan': 'probe', 'mscan': 'probe',
        'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l', 'phf': 'r2l', 'multihop': 'r2l',
        'warezclient': 'r2l', 'warezmaster': 'r2l', 'spy': 'r2l', 'xlock': 'r2l', 'xsnoop': 'r2l',
        'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r', 'rootkit': 'u2r', 'xterm': 'u2r', 'ps': 'u2r',
    }
    
    @classmethod
    def get_category(cls, threat_type: str) -> str:
        """Map threat type to category."""
        return cls.THREAT_SPECIFIC.get(threat_type.lower(), 'anomaly')
    
    @classmethod
    def get_steps(cls, threat_type: str, threat_category: str = None) -> List[str]:
        """Get remediation steps for threat type."""
        if threat_category is None:
            threat_category = cls.get_category(threat_type)
        
        db_entry = cls.REMEDIATION_DB.get(threat_category, cls.REMEDIATION_DB['anomaly'])
        return db_entry['steps']
    
    @classmethod
    def get_title(cls, threat_category: str) -> str:
        """Get alert title for category."""
        return cls.REMEDIATION_DB.get(threat_category, cls.REMEDIATION_DB['anomaly'])['title']
    
    @classmethod
    def format_steps(cls, threat_type: str, threat_category: str = None) -> str:
        """Format steps as HTML for Telegram."""
        steps = cls.get_steps(threat_type, threat_category)
        title = cls.get_title(cls.get_category(threat_type) if threat_category is None else threat_category)
        
        lines = [f"\n🛠 <b>{title}</b>", f"📋 <b>Zalecane kroki:</b>"]
        for i, step in enumerate(steps, 1):
            lines.append(f"  {i}. {step}")
        return "\n".join(lines)


class AlertManager:
    """
    Unified alert manager coordinating Telegram, Windows Toast, and Response Advisor.
    """
    
    def __init__(
        self,
        telegram_bot_token: str = "",
        telegram_chat_id: str = "",
        enable_telegram: bool = True,
        enable_toast: bool = True,
        cooldown_seconds: int = 60,
        min_confidence: float = 0.6
    ):
        self.min_confidence = min_confidence
        
        # Telegram
        self.telegram = None
        if enable_telegram and telegram_bot_token and telegram_chat_id:
            self.telegram = TelegramAlertManager(telegram_bot_token, telegram_chat_id)
            self.telegram.set_cooldown(cooldown_seconds)
        
        # Windows Toast (legacy)
        self.toast = WindowsToastNotifier(enabled=enable_toast)
        
        # Actionable Toast Manager (new)
        self.toast_mgr = None
        if enable_toast:
            try:
                from toast_actions import create_toast_manager
                self.toast_mgr = create_toast_manager(enable_actions=True)
            except Exception as e:
                logger.warning(f"Could not create actionable toast manager: {e}")
        
        # Response advisor
        self.advisor = ResponseAdvisor()
        
        # Alert history
        self.alert_history: List[Alert] = []
        self.max_history = 1000
    
    def set_toast_manager(self, toast_mgr):
        """Set the actionable toast manager."""
        self.toast_mgr = toast_mgr
    
    def update_config(self, telegram_bot_token: str = "", telegram_chat_id: str = "", 
                     enable_telegram: bool = True, enable_toast: bool = True,
                     cooldown_seconds: int = 60, min_confidence: float = 0.6):
        """Update alert manager configuration."""
        # Update Telegram
        if self.telegram:
            self.telegram.set_cooldown(cooldown_seconds)
        
        # Update min_confidence
        self.min_confidence = min_confidence
    
    def alert(self, prediction) -> bool:
        """
        Process prediction and send alerts if anomaly detected.
        
        Args:
            prediction: PredictionResult from InferenceEngine
            
        Returns:
            bool: True if alert was sent
        """
        if not prediction.is_anomaly:
            return False
        
        if prediction.confidence < self.min_confidence:
            logger.debug(f"Confidence {prediction.confidence:.2f} below threshold {self.min_confidence}")
            return False
        
        # Determine threat category
        threat_category = self.advisor.get_category(prediction.threat_type)
        
        # Determine alert level
        if prediction.confidence >= 0.9:
            level = AlertLevel.CRITICAL
        elif prediction.confidence >= 0.75:
            level = AlertLevel.WARNING
        else:
            level = AlertLevel.INFO
        
        # Get remediation steps
        remediation_steps = self.advisor.get_steps(prediction.threat_type, threat_category)
        
        # Create alert
        alert = Alert(
            level=level,
            title=self.advisor.get_title(threat_category),
            message=f"{prediction.threat_type} detected with {prediction.confidence:.1%} confidence",
            threat_type=prediction.threat_type,
            threat_category=threat_category,
            confidence=prediction.confidence,
            flow_info=prediction.flow_features,
            timestamp=datetime.now(),
            remediation_steps=remediation_steps
        )
        
        # Store in history
        self.alert_history.append(alert)
        if len(self.alert_history) > self.max_history:
            self.alert_history.pop(0)
        
        # Send notifications
        sent = False
        
        # Telegram
        if self.telegram:
            if self.telegram.send(alert):
                sent = True
        
        # Actionable Toast (new with action buttons)
        if self.toast_mgr:
            if self.toast_mgr.show_anomaly_alert(
                threat_type=prediction.threat_type,
                threat_category=threat_category,
                confidence=prediction.confidence,
                flow_info=prediction.flow_features
            ):
                sent = True
        
        # Windows Toast (legacy fallback)
        if self.toast.enabled:
            toast_title = f"🛡 {threat_category.upper()}: {prediction.threat_type}"
            toast_msg = f"Confidence: {prediction.confidence:.0%} | {prediction.flow_features.get('src_ip', 'N/A')} → {prediction.flow_features.get('dst_ip', 'N/A')}"
            if self.toast.notify(toast_title, toast_msg):
                sent = True
        
        # Log
        logger.warning(
            f"ALERT [{level.value.upper()}] {prediction.threat_type} ({threat_category}) "
            f"conf={prediction.confidence:.2f} "
            f"src={prediction.flow_features.get('src_ip')} "
            f"dst={prediction.flow_features.get('dst_ip')}"
        )
        
        return sent
    
    def send_test_alert(self) -> bool:
        """Send a test alert to verify configuration."""
        test_prediction = type('obj', (object,), {
            'is_anomaly': True,
            'confidence': 0.95,
            'threat_type': 'test_alert',
            'flow_features': {
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'src_port': 12345,
                'dst_port': 80,
                'protocol': 'TCP',
                'bytes_total': 1024,
                'packets_total': 10
            }
        })()
        
        return self.alert(test_prediction)
    
    def get_recent_alerts(self, limit: int = 50) -> List[Alert]:
        """Get recent alerts."""
        return self.alert_history[-limit:]
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        if not self.alert_history:
            return {'total': 0}
        
        by_category = {}
        by_level = {}
        for a in self.alert_history:
            by_category[a.threat_category] = by_category.get(a.threat_category, 0) + 1
            by_level[a.level.value] = by_level.get(a.level.value, 0) + 1
        
        return {
            'total': len(self.alert_history),
            'by_category': by_category,
            'by_level': by_level,
            'last_alert': self.alert_history[-1].timestamp.isoformat() if self.alert_history else None
        }


def create_alert_manager(
    telegram_bot_token: str = "",
    telegram_chat_id: str = "",
    **kwargs
) -> AlertManager:
    """Factory function to create alert manager."""
    return AlertManager(telegram_bot_token, telegram_chat_id, **kwargs)


if __name__ == "__main__":
    # Test alert manager
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Test ResponseAdvisor
    advisor = ResponseAdvisor()
    print("🧪 ResponseAdvisor test:")
    print(f"  neptune -> {advisor.get_category('neptune')}")
    print(f"  nmap -> {advisor.get_category('nmap')}")
    print(f"  guess_passwd -> {advisor.get_category('guess_passwd')}")
    print(f"  buffer_overflow -> {advisor.get_category('buffer_overflow')}")
    print(f"  unknown -> {advisor.get_category('unknown')}")
    
    steps = advisor.get_steps('neptune', 'dos')
    print(f"\n  DoS steps ({len(steps)}):")
    for s in steps[:3]:
        print(f"    - {s}")
    
    # Test formatting
    formatted = advisor.format_steps('nmap', 'probe')
    print(f"\n  Formatted steps preview:\n{formatted[:200]}...")
#!/usr/bin/env python3
"""
Windows Toast Notifications with Action Buttons
Uses Windows Runtime (winrt) for actionable toasts on Windows 10+.
Fallback to win10toast for older systems.
"""

import json
import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# Check for Windows Runtime support
WINRT_AVAILABLE = False
try:
    if sys.platform == "win32":
        from winrt.windows.data.xml import dom
        from winrt.windows.ui import notifications
        WINRT_AVAILABLE = True
except ImportError:
    pass

# Fallback to win10toast
WIN10TOAST_AVAILABLE = False
try:
    from win10toast import ToastNotifier
    WIN10TOAST_AVAILABLE = True
except ImportError:
    pass


@dataclass
class ToastAction:
    """Represents a toast action button."""
    action_id: str
    title: str
    icon: str = ""
    is_destructive: bool = False


@dataclass
class ToastNotification:
    """Toast notification with actions."""
    title: str
    message: str
    actions: list[ToastAction]
    tag: str = ""
    group: str = ""
    expires_ms: int = 30000
    payload: dict[str, Any] = None


class ActionableToastManager:
    """
    Manages actionable Windows Toast notifications.
    Supports Windows 10+ with winrt, falls back to win10toast.
    """
    
    def __init__(
        self,
        app_id: str = "NetworkGuardian",
        on_action: Callable[[str, dict[str, Any]], None] = None,
        enable_actions: bool = True
    ):
        self.app_id = app_id
        self.on_action = on_action
        self.enable_actions = enable_actions and WINRT_AVAILABLE
        
        # Toast notifier
        self.toast_notifier = None
        self.win10_toaster = None
        
        if self.enable_actions:
            self._init_winrt()
        elif WIN10TOAST_AVAILABLE:
            self._init_win10toast()
        else:
            logger.warning("No toast notification library available")
        
        # Action handlers registry
        self.action_handlers: dict[str, Callable] = {}
        
        # Register COM activator for action handling
        if self.enable_actions:
            self._register_activator()
    
    def _init_winrt(self):
        """Initialize Windows Runtime toast notifier."""
        try:
            self.toast_notifier = notifications.ToastNotificationManager.create_toast_notifier(self.app_id)
            logger.info("✅ WinRT toast notifier initialized")
        except Exception as e:
            logger.error(f"WinRT init failed: {e}")
            self.enable_actions = False
    
    def _init_win10toast(self):
        """Initialize win10toast fallback."""
        try:
            self.win10_toaster = ToastNotifier()
            logger.info("✅ win10toast fallback initialized")
        except Exception as e:
            logger.error(f"win10toast init failed: {e}")
    
    def _register_activator(self):
        """Register COM activator for toast action handling."""
        # This would require a full COM server registration
        # For now, we'll use a simpler approach with protocol handling
        logger.info("Toast action handling via protocol (simplified)")
    
    def register_action_handler(self, action_id: str, handler: Callable[[dict[str, Any]], None]):
        """Register handler for specific action."""
        self.action_handlers[action_id] = handler
        logger.debug(f"Registered handler for action: {action_id}")
    
    def show_toast(self, notification: ToastNotification) -> bool:
        """
        Show toast notification with action buttons.
        
        Args:
            notification: ToastNotification with title, message, actions
            
        Returns:
            bool: True if sent successfully
        """
        if self.enable_actions and self.toast_notifier:
            return self._show_winrt_toast(notification)
        elif self.win10_toaster:
            return self._show_win10toast(notification)
        else:
            logger.warning("No toast backend available")
            return False
    
    def _show_winrt_toast(self, notification: ToastNotification) -> bool:
        """Show toast using Windows Runtime."""
        try:
            # Create toast XML
            xml_content = self._build_toast_xml(notification)
            
            # Parse XML
            xml_doc = dom.XmlDocument()
            xml_doc.load_xml(xml_content)
            
            # Create toast notification
            toast = notifications.ToastNotification(xml_doc)
            toast.tag = notification.tag
            toast.group = notification.group
            toast.expiration_time = datetime.now() + notification.expires_ms / 1000
            
            # Show
            self.toast_notifier.show(toast)
            logger.info(f"WinRT toast shown: {notification.title}")
            return True
            
        except Exception as e:
            logger.error(f"WinRT toast failed: {e}")
            return False
    
    def _build_toast_xml(self, notification: ToastNotification) -> str:
        """Build toast XML with action buttons."""
        # Base template
        actions_xml = ""
        for action in notification.actions:
            actions_xml += f"""
            <action
                activationType="protocol"
                arguments="action={action.action_id}&payload={json.dumps(notification.payload or {})}"
                content="{action.title}"
                imageUri="{action.icon}"
                hint-inputId="{action.action_id}"
            />"""
        
        # Build full XML
        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<toast launch="action=view&payload={json.dumps(notification.payload or {})}">
    <visual>
        <binding template="ToastGeneric">
            <text>{notification.title}</text>
            <text>{notification.message}</text>
        </binding>
    </visual>
    <actions>
        {actions_xml}
    </actions>
</toast>"""
        return xml
    
    def _show_win10toast(self, notification: ToastNotification) -> bool:
        """Show toast using win10toast (no actions)."""
        try:
            self.win10_toaster.show_toast(
                title=notification.title,
                msg=notification.message,
                duration=notification.expires_ms // 1000,
                threaded=True
            )
            logger.info(f"win10toast shown: {notification.title}")
            return True
        except Exception as e:
            logger.error(f"win10toast failed: {e}")
            return False
    
    def handle_action(self, action_id: str, payload: dict[str, Any]):
        """Handle toast action callback."""
        logger.info(f"Toast action triggered: {action_id}")
        
        if action_id in self.action_handlers:
            try:
                self.action_handlers[action_id](payload)
            except Exception as e:
                logger.error(f"Action handler error: {e}")
        else:
            logger.warning(f"No handler for action: {action_id}")
    
    # Convenience methods for common alert types
    def show_anomaly_alert(
        self,
        threat_type: str,
        threat_category: str,
        confidence: float,
        flow_info: dict[str, Any],
        on_quarantine: Callable = None,
        on_whitelist: Callable = None,
        on_dismiss: Callable = None,
        on_settings: Callable = None
    ) -> bool:
        """Show anomaly detection alert with action buttons."""
        
        # Category icons
        cat_icons = {
            'dos': '💥', 'probe': '🔍', 'r2l': '🔓', 
            'u2r': '⬆️', 'normal': '✅', 'unknown': '❓'
        }
        cat_icon = cat_icons.get(threat_category, '⚠️')
        
        # Confidence level
        if confidence >= 0.9:
            level_icon = "🚨"
            level_text = "KRYTYCZNY"
        elif confidence >= 0.75:
            level_icon = "⚠️"
            level_text = "WYSOKI"
        else:
            level_icon = "ℹ️"
            level_text = "ŚREDNI"
        
        payload = {
            "threat_type": threat_type,
            "threat_category": threat_category,
            "confidence": confidence,
            "flow_info": flow_info,
            "timestamp": datetime.now().isoformat()
        }
        
        # Register handlers
        if on_quarantine:
            self.register_action_handler("quarantine", on_quarantine)
        if on_whitelist:
            self.register_action_handler("whitelist", on_whitelist)
        if on_dismiss:
            self.register_action_handler("dismiss", on_dismiss)
        if on_settings:
            self.register_action_handler("settings", on_settings)
        
        actions = [
            ToastAction("quarantine", "🛡 Kwarantanna IP", is_destructive=True),
            ToastAction("whitelist", "✅ Dodaj do białej listy"),
            ToastAction("dismiss", "🗑 Usuń powiadomienie"),
            ToastAction("settings", "⚙️ Ustawienia"),
        ]
        
        src_ip = flow_info.get('src_ip', 'N/A')
        dst_ip = flow_info.get('dst_ip', 'N/A')
        
        notification = ToastNotification(
            title=f"{cat_icon} ANOMALIA: {threat_type} ({level_text})",
            message=(
                f"Źródło: {src_ip} → Cel: {dst_ip}\n"
                f"Pewność: {confidence:.0%} | Kategoria: {threat_category.upper()}"
            ),
            actions=actions,
            tag=f"anomaly_{threat_type}_{src_ip}",
            group="anomalies",
            payload=payload,
            expires_ms=60000  # 1 minute
        )
        
        return self.show_toast(notification)
    
    def show_test_toast(self) -> bool:
        """Show test toast."""
        notification = ToastNotification(
            title="✅ Network Guardian",
            message="Test powiadomienia - system działa poprawnie!",
            actions=[
                ToastAction("settings", "⚙️ Ustawienia"),
                ToastAction("dismiss", "🗑 Zamknij"),
            ],
            tag="test",
            group="system",
            payload={"test": True}
        )
        return self.show_toast(notification)


class ToastActionHandler:
    """
    Handles toast action execution (quarantine, whitelist, etc.)
    """
    
    def __init__(
        self,
        firewall_manager,
        whitelist_manager,
        settings_callback: Callable = None
    ):
        self.firewall = firewall_manager
        self.whitelist = whitelist_manager
        self.settings_callback = settings_callback
    
    def handle_quarantine(self, payload: dict[str, Any]):
        """Quarantine source IP."""
        flow_info = payload.get("flow_info", {})
        src_ip = flow_info.get("src_ip")
        
        if src_ip and src_ip != "N/A":
            try:
                success = self.firewall.block_ip(src_ip, f"Quarantine: {payload.get('threat_type')}")
                if success:
                    logger.info(f"🛡 Quarantined IP: {src_ip}")
                    # Show confirmation toast
                else:
                    logger.error(f"Failed to quarantine {src_ip}")
            except Exception as e:
                logger.error(f"Quarantine error: {e}")
    
    def handle_whitelist(self, payload: dict[str, Any]):
        """Add source IP to whitelist."""
        flow_info = payload.get("flow_info", {})
        src_ip = flow_info.get("src_ip")
        
        if src_ip and src_ip != "N/A":
            try:
                self.whitelist.add_ip(src_ip, f"Whitelisted from alert: {payload.get('threat_type')}")
                logger.info(f"✅ Whitelisted IP: {src_ip}")
            except Exception as e:
                logger.error(f"Whitelist error: {e}")
    
    def handle_dismiss(self, payload: dict[str, Any]):
        """Dismiss alert."""
        logger.info("Alert dismissed by user")
    
    def handle_settings(self, payload: dict[str, Any]):
        """Open settings."""
        logger.info("Opening settings from toast")
        # This would trigger the settings dialog


def create_toast_manager(
    on_action: Callable = None,
    enable_actions: bool = True
) -> ActionableToastManager | None:
    """Factory function to create toast manager."""
    if not WINRT_AVAILABLE and not WIN10TOAST_AVAILABLE:
        logger.warning("No toast notification library available")
        return None
    
    return ActionableToastManager(
        app_id="NetworkGuardian",
        on_action=on_action,
        enable_actions=enable_actions
    )


if __name__ == "__main__":
    # Test
    import logging
    logging.basicConfig(level=logging.INFO)
    
    if WINRT_AVAILABLE:
        print("✅ WinRT available")
        toast = create_toast_manager()
        if toast:
            toast.show_test_toast()
            print("Test toast sent")
    elif WIN10TOAST_AVAILABLE:
        print("✅ win10toast available (fallback)")
    else:
        print("❌ No toast library available")
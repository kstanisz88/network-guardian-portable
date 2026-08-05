#!/usr/bin/env python3
"""
System Tray Manager for Stealth Mode
Handles system tray icon, menu, and window visibility.
"""

import sys
import threading
import logging
from typing import Callable, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

# Optional imports for Windows
try:
    import pystray
    from PIL import Image
    PYSTRAY_AVAILABLE = True
except ImportError:
    PYSTRAY_AVAILABLE = False
    pystray = None
    Image = None


class SystemTrayManager:
    """
    Manages system tray icon and menu for stealth mode.
    """
    
    def __init__(
        self,
        app_name: str = "Network Guardian",
        icon_path: str = "src/icon.ico",
        on_show_window: Callable = None,
        on_hide_window: Callable = None,
        on_settings: Callable = None,
        on_quarantine_ip: Callable = None,
        on_whitelist_ip: Callable = None,
        on_exit: Callable = None,
        get_recent_alerts: Callable = None,
    ):
        self.app_name = app_name
        self.icon_path = icon_path
        self.on_show_window = on_show_window
        self.on_hide_window = on_hide_window
        self.on_settings = on_settings
        self.on_quarantine_ip = on_quarantine_ip
        self.on_whitelist_ip = on_whitelist_ip
        self.on_exit = on_exit
        self.get_recent_alerts = get_recent_alerts
        
        self.icon: Optional[pystray.Icon] = None
        self.tray_thread: Optional[threading.Thread] = None
        self._running = False
        self._window_visible = False
        
        # Load icon
        self._load_icon()
    
    def _load_icon(self):
        """Load tray icon from file."""
        try:
            if PYSTRAY_AVAILABLE and Image:
                self.icon_image = Image.open(self.icon_path)
            else:
                # Create fallback icon
                from PIL import Image, ImageDraw
                img = Image.new('RGBA', (64, 64), (30, 60, 120, 255))
                draw = ImageDraw.Draw(img)
                draw.ellipse([10, 10, 54, 54], fill=(0, 180, 255, 255))
                draw.ellipse([22, 22, 42, 42], fill=(0, 255, 200, 255))
                self.icon_image = img
        except Exception as e:
            logger.warning(f"Could not load icon: {e}")
            # Create minimal fallback
            if PYSTRAY_AVAILABLE and Image:
                self.icon_image = Image.new('RGBA', (64, 64), (30, 60, 120, 255))
            else:
                self.icon_image = None
    
    def start(self):
        """Start system tray in background thread."""
        if not PYSTRAY_AVAILABLE:
            logger.warning("pystray not available, system tray disabled")
            return False
        
        if self._running:
            return True
        
        self._running = True
        self.tray_thread = threading.Thread(target=self._run_tray, daemon=True, name="SystemTray")
        self.tray_thread.start()
        logger.info("🔔 System tray started")
        return True
    
    def _run_tray(self):
        """Run tray icon event loop."""
        try:
            self.icon = pystray.Icon(
                name=self.app_name,
                icon=self.icon_image,
                title=self.app_name,
                menu=self._create_menu()
            )
            self.icon.run()
        except Exception as e:
            logger.error(f"Tray error: {e}")
        finally:
            self._running = False
    
    def _create_menu(self):
        """Create tray menu."""
        return pystray.Menu(
            pystray.MenuItem(
                "🛡 Network Guardian",
                lambda: None,
                enabled=False
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "👁 Pokaż okno" if not self._window_visible else "🙈 Ukryj okno",
                self._toggle_window,
                default=True
            ),
            pystray.MenuItem(
                "⚙️ Ustawienia",
                self._open_settings
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "🛡 Kwarantanna IP",
                self._menu_quarantine_ip
            ),
            pystray.MenuItem(
                "✅ Dodaj do białej listy",
                self._menu_whitelist_ip
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "📋 Ostatnie alerty",
                self._show_recent_alerts
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "❌ Zakończ",
                self._exit_app
            )
        )
    
    def _toggle_window(self, icon=None, item=None):
        """Toggle window visibility."""
        if self._window_visible:
            self.hide_window()
        else:
            self.show_window()
    
    def show_window(self):
        """Show main window."""
        self._window_visible = True
        if self.on_show_window:
            try:
                self.on_show_window()
            except Exception as e:
                logger.error(f"Error showing window: {e}")
        # Update menu
        self._update_menu()
    
    def hide_window(self):
        """Hide main window."""
        self._window_visible = False
        if self.on_hide_window:
            try:
                self.on_hide_window()
            except Exception as e:
                logger.error(f"Error hiding window: {e}")
        self._update_menu()
    
    def _open_settings(self, icon=None, item=None):
        """Open settings dialog."""
        if self.on_settings:
            try:
                self.on_settings()
            except Exception as e:
                logger.error(f"Error opening settings: {e}")
    
    def _menu_quarantine_ip(self, icon=None, item=None):
        """Show IP input dialog for quarantine."""
        self._input_ip_dialog("quarantine")
    
    def _menu_whitelist_ip(self, icon=None, item=None):
        """Show IP input dialog for whitelist."""
        self._input_ip_dialog("whitelist")
    
    def _input_ip_dialog(self, action: str):
        """Show IP input dialog using tkinter."""
        try:
            import tkinter as tk
            from tkinter import simpledialog, messagebox
            
            # Create hidden root
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            
            ip = simpledialog.askstring(
                f"{action.capitalize()} IP",
                f"Wpisz adres IP do {action}:",
                parent=root
            )
            root.destroy()
            
            if ip and self._validate_ip(ip):
                if action == "quarantine" and self.on_quarantine_ip:
                    self.on_quarantine_ip(ip)
                elif action == "whitelist" and self.on_whitelist_ip:
                    self.on_whitelist_ip(ip)
            elif ip:
                messagebox.showerror("Błąd", "Nieprawidłowy adres IP")
        except Exception as e:
            logger.error(f"IP dialog error: {e}")
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IPv4 address."""
        parts = ip.strip().split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    
    def _show_recent_alerts(self, icon=None, item=None):
        """Show recent alerts."""
        if self.get_recent_alerts:
            try:
                alerts = self.get_recent_alerts(10)
                self._show_alerts_window(alerts)
            except Exception as e:
                logger.error(f"Error showing alerts: {e}")
    
    def _show_alerts_window(self, alerts):
        """Show alerts in a window."""
        try:
            import tkinter as tk
            from tkinter import scrolledtext
            
            win = tk.Toplevel() if hasattr(self, '_tk_root') else tk.Tk()
            win.title("Ostatnie alerty")
            win.geometry("600x400")
            
            text = scrolledtext.ScrolledText(win, wrap=tk.WORD)
            text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            if alerts:
                for a in alerts:
                    text.insert(tk.END, f"[{a.get('timestamp', 'N/A')}] {a.get('threat_type', 'N/A')} "
                              f"({a.get('confidence', 0):.0%}) - "
                              f"{a.get('flow_info', {}).get('src_ip', 'N/A')} → "
                              f"{a.get('flow_info', {}).get('dst_ip', 'N/A')}\n")
            else:
                text.insert(tk.END, "Brak alertów\n")
            
            text.config(state=tk.DISABLED)
        except Exception as e:
            logger.error(f"Alerts window error: {e}")
    
    def _exit_app(self, icon=None, item=None):
        """Exit application."""
        logger.info("Exit requested from tray")
        self.stop()
        if self.on_exit:
            self.on_exit()
    
    def _update_menu(self):
        """Update tray menu (recreate icon with new menu)."""
        if self.icon:
            try:
                self.icon.menu = self._create_menu()
                self.icon.update_menu()
            except Exception as e:
                logger.error(f"Menu update error: {e}")
    
    def stop(self):
        """Stop system tray."""
        self._running = False
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass
        if self.tray_thread:
            self.tray_thread.join(timeout=2)
        logger.info("🔔 System tray stopped")
    
    def is_running(self) -> bool:
        return self._running
    
    def notify(self, title: str, message: str, duration: int = 5):
        """Show notification via tray."""
        if self.icon:
            try:
                self.icon.notify(message, title)
            except Exception as e:
                logger.error(f"Tray notify error: {e}")


def create_tray_manager(**kwargs) -> Optional[SystemTrayManager]:
    """Factory function to create tray manager."""
    if not PYSTRAY_AVAILABLE:
        logger.warning("pystray not installed, tray disabled")
        return None
    return SystemTrayManager(**kwargs)


if __name__ == "__main__":
    # Test
    import logging
    logging.basicConfig(level=logging.INFO)
    
    def test_callbacks():
        print("Show window")
        print("Hide window")
        print("Settings")
        print("Quarantine: 192.168.1.100")
        print("Whitelist: 10.0.0.1")
        print("Exit")
    
    tray = create_tray_manager(
        on_show_window=lambda: print("SHOW"),
        on_hide_window=lambda: print("HIDE"),
        on_settings=lambda: print("SETTINGS"),
        on_quarantine_ip=lambda ip: print(f"QUARANTINE {ip}"),
        on_whitelist_ip=lambda ip: print(f"WHITELIST {ip}"),
        on_exit=lambda: print("EXIT"),
    )
    
    if tray:
        tray.start()
        import time
        time.sleep(2)
        tray.stop()
        print("Test done")
#!/usr/bin/env python3
"""
Settings Dialog for Network Guardian
Tabbed interface for all configuration options.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import logging
from typing import Callable, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class SettingsDialog:
    """
    Tabbed settings dialog accessible from system tray.
    """
    
    def __init__(
        self,
        config,
        on_save: Callable = None,
        on_test_telegram: Callable = None,
        parent: tk.Tk = None
    ):
        self.config = config
        self.on_save = on_save
        self.on_test_telegram = on_test_telegram
        self.parent = parent
        self.window: Optional[tk.Toplevel] = None
        self._variables: Dict[str, Any] = {}
        self._test_result_var = None
    
    def show(self):
        """Show settings dialog."""
        if self.window and self.window.winfo_exists():
            self.window.lift()
            self.window.focus_force()
            return
        
        # Create window
        if self.parent:
            self.window = tk.Toplevel(self.parent)
        else:
            self.window = tk.Tk()
        
        self.window.title("Network Guardian - Ustawienia")
        self.window.geometry("650x550")
        self.window.resizable(True, True)
        self.window.minsize(600, 500)
        
        # Center window
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (650 // 2)
        y = (self.window.winfo_screenheight() // 2) - (550 // 2)
        self.window.geometry(f"650x550+{x}+{y}")
        
        # Make modal
        self.window.transient(self.parent)
        self.window.grab_set()
        
        # Protocol
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self._create_widgets()
        self._load_current_config()
        
        if not self.parent:
            self.window.mainloop()
    
    def _create_widgets(self):
        """Create all UI widgets."""
        # Main container
        main_frame = ttk.Frame(self.window, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(
            title_frame, 
            text="⚙️ Network Guardian - Ustawienia", 
            font=("Segoe UI", 16, "bold")
        ).pack(anchor=tk.W)
        
        # Notebook (tabs)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Create tabs
        self._create_general_tab()
        self._create_telegram_tab()
        self._create_alerts_tab()
        self._create_network_tab()
        self._create_upgrade_tab()
        self._create_about_tab()
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="💾 Zapisz", command=self._save, style="Accent.TButton").pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="❌ Anuluj", command=self._on_close).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="🔄 Przywróć domyślne", command=self._reset_defaults).pack(side=tk.LEFT)
        
        # Style
        style = ttk.Style()
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
    
    def _create_general_tab(self):
        """Create General tab."""
        frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(frame, text="🏠 Ogólne")
        
        # Language
        ttk.Label(frame, text="Język interfejsu:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self._variables['language'] = tk.StringVar(value="pl")
        ttk.Combobox(frame, textvariable=self._variables['language'], 
                    values=["pl", "en"], state="readonly", width=10).grid(row=0, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # Theme
        ttk.Label(frame, text="Motyw:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self._variables['theme'] = tk.StringVar(value="system")
        ttk.Combobox(frame, textvariable=self._variables['theme'],
                    values=["system", "light", "dark"], state="readonly", width=10).grid(row=1, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # Auto-start
        self._variables['auto_start'] = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Uruchamiaj automatycznie z systemem", 
                       variable=self._variables['auto_start']).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=10)
        
        # Minimize to tray
        self._variables['minimize_to_tray'] = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Minimalizuj do zasobnika systemowego (Stealth Mode)", 
                       variable=self._variables['minimize_to_tray']).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Log level
        ttk.Label(frame, text="Poziom logów:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self._variables['log_level'] = tk.StringVar(value="INFO")
        ttk.Combobox(frame, textvariable=self._variables['log_level'],
                    values=["DEBUG", "INFO", "WARNING", "ERROR"], state="readonly", width=10).grid(row=4, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        frame.columnconfigure(1, weight=1)
    
    def _create_telegram_tab(self):
        """Create Telegram tab."""
        frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(frame, text="📱 Telegram")
        
        # Enabled
        self._variables['telegram_enabled'] = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Włącz alerty Telegram", 
                       variable=self._variables['telegram_enabled'],
                       command=self._toggle_telegram_fields).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Bot Token
        ttk.Label(frame, text="Bot Token (@BotFather):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self._variables['telegram_bot_token'] = tk.StringVar()
        self.telegram_token_entry = ttk.Entry(frame, textvariable=self._variables['telegram_bot_token'], width=50, show="*")
        self.telegram_token_entry.grid(row=1, column=1, sticky=tk.W+tk.E, pady=5, padx=(10, 0))
        
        # Chat ID
        ttk.Label(frame, text="Chat ID (@userinfobot):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self._variables['telegram_chat_id'] = tk.StringVar()
        self.chat_id_entry = ttk.Entry(frame, textvariable=self._variables['telegram_chat_id'], width=50)
        self.chat_id_entry.grid(row=2, column=1, sticky=tk.W+tk.E, pady=5, padx=(10, 0))
        
        # Test button
        test_frame = ttk.Frame(frame)
        test_frame.grid(row=3, column=0, columnspan=2, pady=15, sticky=tk.W)
        
        ttk.Button(test_frame, text="🔗 Testuj połączenie", command=self._test_telegram).pack(side=tk.LEFT)
        self._test_result_var = tk.StringVar()
        ttk.Label(test_frame, textvariable=self._test_result_var, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=10)
        
        # Help text
        help_text = (
            "Jak skonfigurować Telegram:\n"
            "1. Otwórz Telegram i napisz do @BotFather → /newbot → skopiuj token\n"
            "2. Napisz do @userinfobot → skopiuj swój Chat ID (liczba)\n"
            "3. Wklej oba pola powyżej i kliknij 'Testuj połączenie'"
        )
        ttk.Label(frame, text=help_text, font=("Segoe UI", 8), foreground="gray", justify=tk.LEFT).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=10)
        
        frame.columnconfigure(1, weight=1)
        self._telegram_fields = [self.telegram_token_entry, self.chat_id_entry]
    
    def _toggle_telegram_fields(self):
        """Enable/disable Telegram fields based on checkbox."""
        state = tk.NORMAL if self._variables['telegram_enabled'].get() else tk.DISABLED
        for widget in self._telegram_fields:
            widget.config(state=state)
    
    def _create_alerts_tab(self):
        """Create Alerts tab."""
        frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(frame, text="🔔 Alerty")
        
        # Windows Toast
        self._variables['enable_windows_toast'] = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Włącz powiadomienia Windows Toast (z przyciskami akcji)", 
                       variable=self._variables['enable_windows_toast']).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Action buttons info
        ttk.Label(frame, text="Powiadomienia zawierają przyciski: 🛡 Kwarantanna, ✅ Białą listę, 🗑 Usuń, ⚙️ Ustawienia",
                 font=("Segoe UI", 8), foreground="blue").grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # Cooldown
        ttk.Label(frame, text="Cooldown między alertami (sekundy):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self._variables['cooldown_seconds'] = tk.IntVar(value=60)
        ttk.Spinbox(frame, from_=10, to=3600, textvariable=self._variables['cooldown_seconds'], width=10).grid(row=2, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # Min confidence
        ttk.Label(frame, text="Minimalna pewność alertu (0.0-1.0):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self._variables['min_confidence'] = tk.DoubleVar(value=0.6)
        ttk.Spinbox(frame, from_=0.1, to=0.99, increment=0.05, textvariable=self._variables['min_confidence'], width=10).grid(row=3, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # Whitelist IPs
        ttk.Label(frame, text="Biała lista IP (po przecinku):").grid(row=4, column=0, sticky=tk.W, pady=5)
        self._variables['whitelist_ips'] = tk.StringVar()
        ttk.Entry(frame, textvariable=self._variables['whitelist_ips'], width=50).grid(row=4, column=1, sticky=tk.W+tk.E, pady=5, padx=(10, 0))
        
        frame.columnconfigure(1, weight=1)
    
    def _create_network_tab(self):
        """Create Network tab."""
        frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(frame, text="🌐 Sieć")
        
        # Interface
        ttk.Label(frame, text="Interfejs sieciowy:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self._variables['interface'] = tk.StringVar(value="auto")
        ttk.Entry(frame, textvariable=self._variables['interface'], width=30).grid(row=0, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        ttk.Label(frame, text="(auto = auto-detekcja, np. Ethernet, Wi-Fi)", font=("Segoe UI", 8), foreground="gray").grid(row=1, column=1, sticky=tk.W, padx=(10, 0))
        
        # BPF Filter
        ttk.Label(frame, text="Filtr BPF (opcjonalnie):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self._variables['bpf_filter'] = tk.StringVar()
        ttk.Entry(frame, textvariable=self._variables['bpf_filter'], width=50).grid(row=2, column=1, sticky=tk.W+tk.E, pady=5, padx=(10, 0))
        ttk.Label(frame, text="(np. 'tcp port 80 or tcp port 443')", font=("Segoe UI", 8), foreground="gray").grid(row=3, column=1, sticky=tk.W, padx=(10, 0))
        
        # Timeouts
        ttk.Label(frame, text="Idle timeout (s):").grid(row=4, column=0, sticky=tk.W, pady=5)
        self._variables['idle_timeout'] = tk.IntVar(value=120)
        ttk.Spinbox(frame, from_=30, to=3600, textvariable=self._variables['idle_timeout'], width=10).grid(row=4, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # Connection tracking
        self._variables['connection_tracking'] = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Włącz śledzenie połączeń (ct_* features)", 
                       variable=self._variables['connection_tracking']).grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=10)
        
        frame.columnconfigure(1, weight=1)
    
    def _create_upgrade_tab(self):
        """Create Upgrade tab."""
        frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(frame, text="🔄 Aktualizacje")
        
        # Enabled
        self._variables['upgrade_enabled'] = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Włącz automatyczne sprawdzanie aktualizacji modelu", 
                       variable=self._variables['upgrade_enabled']).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Interval
        ttk.Label(frame, text="Interwał sprawdzania (godziny):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self._variables['upgrade_interval'] = tk.IntVar(value=6)
        ttk.Spinbox(frame, from_=1, to=168, textvariable=self._variables['upgrade_interval'], width=10).grid(row=1, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # Manifest URL
        ttk.Label(frame, text="URL manifestu:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self._variables['manifest_url'] = tk.StringVar()
        ttk.Entry(frame, textvariable=self._variables['manifest_url'], width=60).grid(row=2, column=1, sticky=tk.W+tk.E, pady=5, padx=(10, 0))
        
        # Current version info
        ttk.Label(frame, text="Wersja aplikacji: 1.0.0", font=("Segoe UI", 9)).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=10)
        
        # Check now button
        ttk.Button(frame, text="🔍 Sprawdź teraz", command=self._check_upgrade_now).grid(row=4, column=0, sticky=tk.W, pady=5)
        
        frame.columnconfigure(1, weight=1)
    
    def _create_about_tab(self):
        """Create About tab."""
        frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(frame, text="ℹ️ O programie")
        
        about_text = """🛡 Network Guardian Portable v1.0.0

Lekki, przenośny system wykrywania anomalii w ruchu sieciowym
oparty na uczeniu maszynowym (ML).

🔧 Technologie:
• nfstream - przechwytywanie przepływów sieciowych
• scikit-learn, XGBoost, LightGBM - ensemble ML
• RandomForest + XGBoost + LightGBM (soft voting)
• nfstream connection tracking (ct_* features)

🎯 Wykrywane zagrożenia:
• DoS (neptune, smurf, back, pod, teardrop)
• Probe/Scan (nmap, ipsweep, portsweep, satan)
• R2L (guess_passwd, ftp_write, imap, phf)
• U2R (buffer_overflow, rootkit, perl)
• Data Exfiltration
• Malware C2 / Beaconing

🔄 Auto-upgrade:
• Sprawdzanie co 6h (konfigurowalne)
• Manifest z GitHub Pages + SHA256
• Hot-swap modeli bez restartu

📱 Alerty:
• Telegram Bot API (HTML)
• Windows Toast z przyciskami akcji
• System Tray (Stealth Mode)

📄 Licencja: MIT
👨‍💻 Autor: Network Guardian Team
"""
        
        text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=("Consolas", 9))
        text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        text.insert(tk.END, about_text)
        text.config(state=tk.DISABLED)
    
    def _load_current_config(self):
        """Load current config into UI variables."""
        # General
        self._variables['language'].set(self.config.get("language", "pl"))
        self._variables['theme'].set(self.config.get("theme", "system"))
        self._variables['auto_start'].set(self.config.get("auto_start", False))
        self._variables['minimize_to_tray'].set(self.config.get("minimize_to_tray", True))
        self._variables['log_level'].set(self.config.get("log_level", "INFO"))
        
        # Telegram
        tg = self.config.get_telegram_config()
        self._variables['telegram_enabled'].set(tg.get("enabled", False))
        self._variables['telegram_bot_token'].set(tg.get("bot_token", ""))
        self._variables['telegram_chat_id'].set(tg.get("chat_id", ""))
        self._toggle_telegram_fields()
        
        # Alerts
        alerts = self.config.get_alerts_config()
        self._variables['enable_windows_toast'].set(alerts.get("enable_windows_toast", True))
        self._variables['cooldown_seconds'].set(alerts.get("cooldown_seconds", 60))
        self._variables['min_confidence'].set(alerts.get("min_confidence", 0.6))
        self._variables['whitelist_ips'].set(alerts.get("whitelist_ips", ""))
        
        # Network
        net = self.config.get_network_config()
        self._variables['interface'].set(net.get("interface", "auto"))
        self._variables['bpf_filter'].set(net.get("bpf_filter", ""))
        self._variables['idle_timeout'].set(net.get("idle_timeout", 120))
        self._variables['connection_tracking'].set(net.get("enable_connection_tracking", True))
        
        # Upgrade
        upg = self.config.get_upgrade_config()
        self._variables['upgrade_enabled'].set(upg.get("enabled", True))
        self._variables['upgrade_interval'].set(upg.get("check_interval_hours", 6))
        self._variables['manifest_url'].set(upg.get("manifest_url", 
            "https://raw.githubusercontent.com/kstanisz88/anomaly-detector/main/model_manifest.json"))
    
    def _test_telegram(self):
        """Test Telegram connection."""
        token = self._variables['telegram_bot_token'].get().strip()
        chat_id = self._variables['telegram_chat_id'].get().strip()
        
        if not token or not chat_id:
            self._test_result_var.set("❌ Wypełnij oba pola")
            return
        
        self._test_result_var.set("⏳ Testowanie...")
        self.window.update()
        
        def test():
            import requests
            try:
                # Test bot
                resp = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=10)
                if resp.status_code != 200:
                    self.window.after(0, lambda: self._test_result_var.set(f"❌ Bot error: {resp.status_code}"))
                    return
                
                bot_info = resp.json()
                if not bot_info.get("ok"):
                    self.window.after(0, lambda: self._test_result_var.set("❌ Invalid token"))
                    return
                
                # Test send message
                resp = requests.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={
                        "chat_id": chat_id,
                        "text": "✅ <b>Network Guardian</b> - Test połączenia z ustawień!",
                        "parse_mode": "HTML"
                    },
                    timeout=10
                )
                if resp.status_code == 200:
                    self.window.after(0, lambda: self._test_result_var.set("✅ OK - Sprawdź Telegram!"))
                else:
                    self.window.after(0, lambda: self._test_result_var.set(f"❌ Send failed: {resp.status_code}"))
            except Exception as e:
                self.window.after(0, lambda: self._test_result_var.set(f"❌ Error: {e}"))
        
        threading.Thread(target=test, daemon=True).start()
    
    def _check_upgrade_now(self):
        """Trigger immediate upgrade check."""
        messagebox.showinfo("Sprawdzanie", "Funkcja sprawdzania aktualizacji zostanie dodana w przyszłej wersji.")
    
    def _reset_defaults(self):
        """Reset to default values."""
        if messagebox.askyesno("Potwierdzenie", "Przywrócić ustawienia domyślne?"):
            self.config._config = self.config._default_config()
            self._load_current_config()
    
    def _save(self):
        """Save configuration."""
        # General
        self.config.set("language", self._variables['language'].get())
        self.config.set("theme", self._variables['theme'].get())
        self.config.set("auto_start", self._variables['auto_start'].get())
        self.config.set("minimize_to_tray", self._variables['minimize_to_tray'].get())
        self.config.set("log_level", self._variables['log_level'].get())
        
        # Telegram
        self.config.set("telegram.enabled", self._variables['telegram_enabled'].get())
        self.config.set("telegram.bot_token", self._variables['telegram_bot_token'].get().strip())
        self.config.set("telegram.chat_id", self._variables['telegram_chat_id'].get().strip())
        
        # Alerts
        self.config.set("alerts.enable_windows_toast", self._variables['enable_windows_toast'].get())
        self.config.set("alerts.cooldown_seconds", self._variables['cooldown_seconds'].get())
        self.config.set("alerts.min_confidence", self._variables['min_confidence'].get())
        self.config.set("alerts.whitelist_ips", self._variables['whitelist_ips'].get())
        
        # Network
        self.config.set("network.interface", self._variables['interface'].get())
        self.config.set("network.bpf_filter", self._variables['bpf_filter'].get())
        self.config.set("network.idle_timeout", self._variables['idle_timeout'].get())
        self.config.set("network.enable_connection_tracking", self._variables['connection_tracking'].get())
        
        # Upgrade
        self.config.set("upgrade.enabled", self._variables['upgrade_enabled'].get())
        self.config.set("upgrade.check_interval_hours", self._variables['upgrade_interval'].get())
        self.config.set("upgrade.manifest_url", self._variables['manifest_url'].get())
        
        # Call save callback
        if self.on_save:
            self.on_save()
        
        messagebox.showinfo("Sukces", "Ustawienia zapisane pomyślnie!")
        self._on_close()
    
    def _on_close(self):
        """Close dialog."""
        if self.window:
            self.window.grab_release()
            self.window.destroy()
            self.window = None
    
    def _save_and_close(self):
        """Save and close."""
        self._save()
        self._on_close()


def create_settings_dialog(config, on_save=None, on_test_telegram=None, parent=None) -> SettingsDialog:
    """Factory function to create settings dialog."""
    return SettingsDialog(config, on_save, on_test_telegram, parent)


if __name__ == "__main__":
    # Test
    import logging
    logging.basicConfig(level=logging.INFO)
    
    from portable_config import PortableConfig
    from pathlib import Path
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        config = PortableConfig(Path(tmpdir))
        config.set("telegram.bot_token", "test")
        config.set("telegram.chat_id", "123")
        
        def on_save():
            print("Config saved!")
        
        dialog = SettingsDialog(config, on_save=on_save)
        dialog.show()
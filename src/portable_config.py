#!/usr/bin/env python3
"""
Portable Configuration Manager
Handles first-run setup UI and persistent config storage.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading


class PortableConfig:
    """Manages portable configuration with first-run setup UI."""
    
    CONFIG_FILENAME = "network_guardian_config.json"
    
    def __init__(self, app_dir: Path = None):
        # App directory is where the .exe lives (or script directory in dev)
        if app_dir is None:
            if getattr(sys, 'frozen', False):
                # Running as PyInstaller bundle
                self.app_dir = Path(sys.executable).parent
            else:
                # Running as script
                self.app_dir = Path(__file__).parent.parent
        else:
            self.app_dir = app_dir
        
        self.config_path = self.app_dir / self.CONFIG_FILENAME
        self.models_dir = self.app_dir / "models"
        self._config: Dict[str, Any] = {}
        self._load()
    
    def _load(self):
        """Load config from file."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self._config = json.load(f)
            except Exception:
                self._config = {}
        else:
            self._config = self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            "first_run": True,
            "telegram": {
                "bot_token": "",
                "chat_id": "",
                "enabled": False
            },
            "alerts": {
                "enable_windows_toast": True,
                "cooldown_seconds": 60,
                "min_confidence": 0.6
            },
            "network": {
                "interface": "auto",
                "bpf_filter": "",
                "idle_timeout": 120,
                "enable_connection_tracking": True
            },
            "model": {
                "threshold": 0.6,
                "auto_download": True
            },
            "upgrade": {
                "manifest_url": "https://raw.githubusercontent.com/kstanisz88/anomaly-detector/main/model_manifest.json",
                "check_interval_hours": 6,
                "enabled": True
            },
            "stealth": {
                "enabled": True,
                "minimize_to_tray": True,
                "auto_start": False
            }
        }
    
    def save(self):
        """Save config to file."""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Failed to save config: {e}")
    
    def is_first_run(self) -> bool:
        """Check if this is the first run."""
        return self._config.get("first_run", True)
    
    def mark_first_run_complete(self):
        """Mark first run as complete."""
        self._config["first_run"] = False
        self.save()
    
    def get(self, key: str, default=None):
        """Get config value with dot notation (e.g., 'telegram.bot_token')."""
        keys = key.split('.')
        val = self._config
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k)
            else:
                return default
            if val is None:
                return default
        return val
    
    def set(self, key: str, value: Any):
        """Set config value with dot notation."""
        keys = key.split('.')
        val = self._config
        for k in keys[:-1]:
            if k not in val:
                val[k] = {}
            val = val[k]
        val[keys[-1]] = value
        self.save()
    
    def get_telegram_config(self) -> Dict[str, Any]:
        """Get telegram configuration."""
        return self._config.get("telegram", {})
    
    def get_alerts_config(self) -> Dict[str, Any]:
        """Get alerts configuration."""
        return self._config.get("alerts", {})
    
    def get_network_config(self) -> Dict[str, Any]:
        """Get network configuration."""
        return self._config.get("network", {})
    
    def get_model_config(self) -> Dict[str, Any]:
        """Get model configuration."""
        return self._config.get("model", {})
    
    def get_upgrade_config(self) -> Dict[str, Any]:
        """Get upgrade configuration."""
        return self._config.get("upgrade", {})


class FirstRunSetupUI:
    """First-run setup GUI using tkinter."""
    
    def __init__(self, config: PortableConfig):
        self.config = config
        self.result = False
        self.root = None
    
    def run(self) -> bool:
        """Show setup dialog and return True if configuration saved."""
        self.root = tk.Tk()
        self.root.title("Network Guardian - Pierwsza konfiguracja")
        self.root.geometry("550x650")
        self.root.resizable(False, False)
        self.root.eval('tk::PlaceWindow . center')
        
        # Icon
        try:
            self.root.iconbitmap(default='')
        except:
            pass
        
        self._create_widgets()
        self.root.mainloop()
        return self.result
    
    def _create_widgets(self):
            # Main frame with scroll
            canvas = tk.Canvas(self.root)
            scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)
        
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
        
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
        
            canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
            scrollbar.pack(side="right", fill="y")
        
            # Title
            title_frame = ttk.Frame(scrollable_frame)
            title_frame.pack(fill="x", pady=(0, 20))
        
            ttk.Label(
                title_frame, 
                text="🛡 Network Guardian", 
                font=("Segoe UI", 18, "bold")
            ).pack()
            ttk.Label(
                title_frame, 
                text="Konfiguracja pierwszego uruchomienia", 
                font=("Segoe UI", 10),
                foreground="gray"
            ).pack()
        
            ttk.Label(
                title_frame, 
                text="Konfiguracja alertów Telegram (opcjonalna - możesz pominąć i skonfigurować później w Ustawieniach)", 
                font=("Segoe UI", 9),
                foreground="gray"
            ).pack(anchor="w", pady=(5, 0))
        
            # Telegram section
            telegram_frame = ttk.LabelFrame(scrollable_frame, text="📱 Telegram Alerts", padding=15)
            telegram_frame.pack(fill="x", pady=(0, 15))
        
            # Enabled checkbox
            self.telegram_enabled_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(telegram_frame, text="Włącz alerty Telegram", 
                           variable=self.telegram_enabled_var,
                           command=self._toggle_telegram_fields).pack(anchor="w", pady=(0, 10))
        
            # Bot Token
            ttk.Label(telegram_frame, text="Bot Token (z @BotFather):").pack(anchor="w")
            self.bot_token_var = tk.StringVar()
            self.telegram_token_entry = ttk.Entry(telegram_frame, textvariable=self.bot_token_var, width=60, show="*")
            self.telegram_token_entry.pack(fill="x", pady=(5, 10))
        
            # Chat ID
            ttk.Label(telegram_frame, text="Chat ID (z @userinfobot):").pack(anchor="w")
            self.chat_id_var = tk.StringVar()
            self.chat_id_entry = ttk.Entry(telegram_frame, textvariable=self.chat_id_var, width=60)
            self.chat_id_entry.pack(fill="x", pady=(5, 10))
        
            # Test button
            test_frame = ttk.Frame(telegram_frame)
            test_frame.pack(fill="x", pady=10)
            ttk.Button(test_frame, text="🔗 Testuj połączenie", command=self._test_telegram).pack(side="left")
            self.test_result_var = tk.StringVar()
            ttk.Label(test_frame, textvariable=self.test_result_var, font=("Segoe UI", 8)).pack(side="left", padx=10)
        
            # Help text
            help_text = (
                "Jak uzyskać dane:\n"
                "1. Otwórz Telegram i napisz do @BotFather → /newbot → skopiuj token\n"
                "2. Napisz do @userinfobot → skopiuj swój Chat ID (liczba)\n"
                "3. Wklej oba pola powyżej i kliknij 'Testuj połączenie'\n\n"
                "Możesz to pominąć i skonfigurować później w Ustawieniach (ikona w zasobniku systemowym)."
            )
            ttk.Label(telegram_frame, text=help_text, font=("Segoe UI", 8), foreground="gray", justify="left").pack(anchor="w", pady=(10, 0))
        
            self._telegram_fields = [self.telegram_token_entry, self.chat_id_entry]
            self._toggle_telegram_fields()  # Initially disabled
        
            # Windows Toast section
            toast_frame = ttk.LabelFrame(scrollable_frame, text="🪟 Powiadomienia systemowe", padding=15)
            toast_frame.pack(fill="x", pady=(0, 15))
        
            self.toast_enabled_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(toast_frame, text="Włącz powiadomienia Windows Toast (z przyciskami akcji: Kwarantanna, Biała lista, Usuń, Ustawienia)", 
                           variable=self.toast_enabled_var).pack(anchor="w")
        
            ttk.Label(toast_frame, text="Cooldown między alertami (sekundy):").pack(anchor="w", pady=(10, 0))
            self.cooldown_var = tk.IntVar(value=60)
            ttk.Spinbox(toast_frame, from_=10, to=3600, textvariable=self.cooldown_var, width=10).pack(anchor="w", pady=(5, 0))
        
            ttk.Label(toast_frame, text="Minimalna pewność alertu (0.0-1.0):").pack(anchor="w", pady=(10, 0))
            self.min_conf_var = tk.DoubleVar(value=0.6)
            ttk.Spinbox(toast_frame, from_=0.1, to=0.99, increment=0.05, textvariable=self.min_conf_var, width=10).pack(anchor="w", pady=(5, 0))
        
            # Stealth mode
            stealth_frame = ttk.LabelFrame(scrollable_frame, text="🥷 Tryb Stealth (Ukryty)", padding=15)
            stealth_frame.pack(fill="x", pady=(0, 15))
        
            self.stealth_mode_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(stealth_frame, text="Uruchamiaj w trybie Stealth (tylko ikona w zasobniku, bez okna konsoli)", 
                           variable=self.stealth_mode_var).pack(anchor="w", pady=5)
        
            self.minimize_to_tray_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(stealth_frame, text="Minimalizuj do zasobnika systemowego przy zamknięciu okna", 
                           variable=self.minimize_to_tray_var).pack(anchor="w", pady=5)
        
            # Auto-start
            self.auto_start_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(stealth_frame, text="Uruchamiaj automatycznie z systemem Windows", 
                           variable=self.auto_start_var).pack(anchor="w", pady=5)
        
            # Network section
            net_frame = ttk.LabelFrame(scrollable_frame, text="🌐 Sieć", padding=15)
            net_frame.pack(fill="x", pady=(0, 15))
        
            ttk.Label(net_frame, text="Interfejs sieciowy (auto = auto-detekcja):").pack(anchor="w")
            self.interface_var = tk.StringVar(value="auto")
            ttk.Entry(net_frame, textvariable=self.interface_var, width=30).pack(anchor="w", pady=(5, 0))
        
            self.tracking_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(net_frame, text="Włącz śledzenie połączeń (ct_* features)", variable=self.tracking_var).pack(anchor="w", pady=(10, 0))
        
            # Model section
            model_frame = ttk.LabelFrame(scrollable_frame, text="🤖 Model ML", padding=15)
            model_frame.pack(fill="x", pady=(0, 15))
        
            ttk.Label(model_frame, text="Próg wykrywania anomalii (0.0-1.0):").pack(anchor="w")
            self.threshold_var = tk.DoubleVar(value=0.6)
            ttk.Spinbox(model_frame, from_=0.1, to=0.99, increment=0.05, textvariable=self.threshold_var, width=10).pack(anchor="w", pady=(5, 0))
        
            self.auto_download_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(model_frame, text="Automatycznie pobieraj modele przy starcie", variable=self.auto_download_var).pack(anchor="w", pady=(10, 0))
        
            # Auto-upgrade section
            upgrade_frame = ttk.LabelFrame(scrollable_frame, text="🔄 Automatyczne aktualizacje", padding=15)
            upgrade_frame.pack(fill="x", pady=(0, 15))
        
            self.upgrade_enabled_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(upgrade_frame, text="Włącz automatyczne sprawdzanie aktualizacji modelu", variable=self.upgrade_enabled_var).pack(anchor="w")
        
            ttk.Label(upgrade_frame, text="Interwał sprawdzania (godziny):").pack(anchor="w", pady=(10, 0))
            self.upgrade_interval_var = tk.IntVar(value=6)
            ttk.Spinbox(upgrade_frame, from_=1, to=168, textvariable=self.upgrade_interval_var, width=10).pack(anchor="w", pady=(5, 0))
        
            ttk.Label(upgrade_frame, text="URL manifestu (GitHub Pages / raw.githubusercontent.com):").pack(anchor="w", pady=(10, 0))
            self.manifest_url_var = tk.StringVar(value="https://raw.githubusercontent.com/kstanisz88/anomaly-detector/main/model_manifest.json")
            ttk.Entry(upgrade_frame, textvariable=self.manifest_url_var, width=60).pack(fill="x", pady=(5, 0))
        
            # Buttons
            btn_frame = ttk.Frame(scrollable_frame)
            btn_frame.pack(fill="x", pady=20)
        
            ttk.Button(btn_frame, text="💾 Zapisz i uruchom", command=self._save_and_run, style="Accent.TButton").pack(side="right", padx=5)
            ttk.Button(btn_frame, text="⏭ Pomiń konfigurację Telegram", command=self._skip_telegram).pack(side="right", padx=5)
            ttk.Button(btn_frame, text="❌ Anuluj", command=self._cancel).pack(side="right")
        
            # Style
            style = ttk.Style()
            style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
    
    def _test_telegram(self):
        """Test Telegram bot connection."""
        import requests
        token = self.bot_token_var.get().strip()
        chat_id = self.chat_id_var.get().strip()
        
        if not token or not chat_id:
            self.test_result_var.set("❌ Wypełnij oba pola")
            return
        
        self.test_result_var.set("⏳ Testowanie...")
        self.root.update()
        
        def test():
            try:
                # Test bot
                resp = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=10)
                if resp.status_code != 200:
                    self.root.after(0, lambda: self.test_result_var.set(f"❌ Bot error: {resp.status_code}"))
                    return
                
                bot_info = resp.json()
                if not bot_info.get("ok"):
                    self.root.after(0, lambda: self.test_result_var.set("❌ Invalid token"))
                    return
                
                # Test send message
                resp = requests.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={
                        "chat_id": chat_id,
                        "text": "✅ <b>Network Guardian</b> - Test połączenia udany!",
                        "parse_mode": "HTML"
                    },
                    timeout=10
                )
                if resp.status_code == 200:
                    self.root.after(0, lambda: self.test_result_var.set("✅ OK - Sprawdź Telegram!"))
                else:
                    self.root.after(0, lambda: self.test_result_var.set(f"❌ Send failed: {resp.status_code}"))
            except Exception as e:
                self.root.after(0, lambda: self.test_result_var.set(f"❌ Error: {e}"))
        
        threading.Thread(target=test, daemon=True).start()
    
    def _save_and_run(self):
        """Save configuration and close dialog."""
        # Validate required fields
        if not self.bot_token_var.get().strip() or not self.chat_id_var.get().strip():
            messagebox.showerror("Błąd", "Bot Token i Chat ID są wymagane!")
            return
        
        # Save to config
        self.config.set("telegram.bot_token", self.bot_token_var.get().strip())
        self.config.set("telegram.chat_id", self.chat_id_var.get().strip())
        self.config.set("telegram.enabled", True)
        
        self.config.set("alerts.enable_windows_toast", self.toast_enabled_var.get())
        self.config.set("alerts.cooldown_seconds", self.cooldown_var.get())
        self.config.set("alerts.min_confidence", self.min_conf_var.get())
        
        self.config.set("network.interface", self.interface_var.get())
        self.config.set("network.enable_connection_tracking", self.tracking_var.get())
        
        self.config.set("model.threshold", self.threshold_var.get())
        self.config.set("model.auto_download", self.auto_download_var.get())
        
        self.config.set("upgrade.enabled", self.upgrade_enabled_var.get())
        self.config.set("upgrade.check_interval_hours", self.upgrade_interval_var.get())
        self.config.set("upgrade.manifest_url", self.manifest_url_var.get())
        
        self.config.mark_first_run_complete()
        
        self.result = True
        self.root.destroy()
    
    def _cancel(self):
        """Cancel setup."""
        self.result = False
        self.root.destroy()
    
    def _skip_telegram(self):
        """Skip Telegram configuration - save with telegram disabled."""
        # Save to config with telegram disabled
        self.config.set("telegram.enabled", False)
        self.config.set("telegram.bot_token", "")
        self.config.set("telegram.chat_id", "")
        
        self.config.set("alerts.enable_windows_toast", self.toast_enabled_var.get())
        self.config.set("alerts.cooldown_seconds", self.cooldown_var.get())
        self.config.set("alerts.min_confidence", self.min_conf_var.get())
        
        self.config.set("network.interface", self.interface_var.get())
        self.config.set("network.enable_connection_tracking", self.tracking_var.get())
        
        self.config.set("model.threshold", self.threshold_var.get())
        self.config.set("model.auto_download", self.auto_download_var.get())
        
        self.config.set("upgrade.enabled", self.upgrade_enabled_var.get())
        self.config.set("upgrade.check_interval_hours", self.upgrade_interval_var.get())
        self.config.set("upgrade.manifest_url", self.manifest_url_var.get())
        
        self.config.mark_first_run_complete()
        
        self.result = True
        self.root.destroy()
    
    def _toggle_telegram_fields(self):
        """Enable/disable Telegram fields based on checkbox."""
        state = "normal" if self.telegram_enabled_var.get() else "disabled"
        for widget in [self.telegram_token_entry, self.chat_id_entry]:
            widget.config(state=state)


def run_first_run_setup(config: PortableConfig) -> bool:
    """Run first-run setup UI. Returns True if configured successfully."""
    try:
        ui = FirstRunSetupUI(config)
        return ui.run()
    except Exception as e:
        print(f"GUI setup failed: {e}")
        # Fallback to console
        return _console_first_run_setup(config)


def _console_first_run_setup(config: PortableConfig) -> bool:
    """Console-based first-run setup fallback."""
    print("\n" + "="*60)
    print("🛡 NETWORK GUARDIAN - PIERWSZA KONFIGURACJA")
    print("="*60)
    
    print("\n📱 TELEGRAM (opcjonalne - możesz pominąć):")
    print("  1. @BotFather → /newbot → skopiuj token")
    print("  2. @userinfobot → skopiuj Chat ID")
    
    bot_token = input("\nBot Token (Enter = pominąć): ").strip()
    if not bot_token:
        print("⏭ Pomijam konfigurację Telegram...")
        chat_id = ""
        enable_telegram = False
    else:
        chat_id = input("Chat ID: ").strip()
        if not chat_id:
            print("❌ Chat ID wymagany!")
            return False
        enable_telegram = True
    
    # Optional settings
    print("\n⚙️ Ustawienia opcjonalne (Enter = domyślne):")
    
    toast = input("Windows Toast notifications? (T/n): ").strip().lower()
    enable_toast = toast != 'n'
    
    cooldown = input("Cooldown alertów [60s]: ").strip()
    cooldown = int(cooldown) if cooldown else 60
    
    threshold = input("Próg anomalii [0.6]: ").strip()
    threshold = float(threshold) if threshold else 0.6
    
    stealth = input("Tryb Stealth (ukryty w zasobniku)? (T/n): ").strip().lower()
    enable_stealth = stealth != 'n'
    
    # Save
    config.set("telegram.bot_token", bot_token)
    config.set("telegram.chat_id", chat_id)
    config.set("telegram.enabled", enable_telegram)
    config.set("alerts.enable_windows_toast", enable_toast)
    config.set("alerts.cooldown_seconds", cooldown)
    config.set("alerts.min_confidence", threshold)
    config.set("model.threshold", threshold)
    config.set("stealth.enabled", enable_stealth)
    config.mark_first_run_complete()
    
    print("\n✅ Konfiguracja zapisana!")
    return True


if __name__ == "__main__":
    # Test
    config = PortableConfig(Path("."))
    if config.is_first_run():
        success = run_first_run_setup(config)
        print(f"Setup result: {success}")
    else:
        print("Config already exists:", config.config_path)
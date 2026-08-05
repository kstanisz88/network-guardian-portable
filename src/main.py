#!/usr/bin/env python3
"""
Network Guardian - Portable Version with Stealth Mode, System Tray, Settings, and Actionable Alerts
"""

import sys
import signal
import time
import logging
import argparse
import threading
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from portable_config import PortableConfig, run_first_run_setup
from capture_module import FlowCapture, create_capture
from inference_engine import InferenceEngine, create_inference_engine
from alert_manager import AlertManager, create_alert_manager
from auto_upgrade import AutoUpgrader, create_auto_upgrader
from system_tray import SystemTrayManager, create_tray_manager
from settings_dialog import SettingsDialog, create_settings_dialog
from toast_actions import ActionableToastManager, ToastActionHandler, create_toast_manager
from firewall_manager import FirewallManager, create_firewall_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('network_guardian.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)


class NetworkGuardian:
    """
    Main Network Guardian application - Portable Version with Stealth Mode.
    """

    def __init__(self, config: PortableConfig):
        self.config = config
        self.app_dir = config.app_dir
        
        # Components
        self.capture: Optional[FlowCapture] = None
        self.engine: Optional[InferenceEngine] = None
        self.alert_mgr: Optional[AlertManager] = None
        self.upgrader: Optional[AutoUpgrader] = None
        self.tray: Optional[SystemTrayManager] = None
        self.toast_mgr: Optional[ActionableToastManager] = None
        self.firewall: Optional[FirewallManager] = None
        self.toast_handler: Optional[ToastActionHandler] = None
        
        # State
        self.running = False
        self.last_alert_time = 0
        self.stats = {
            'flows_processed': 0,
            'anomalies_detected': 0,
            'alerts_sent': 0,
            'start_time': 0,
            'last_flow_time': 0
        }
        
        # Progress callback for UI
        self._progress_callback = None
        self._progress_window = None
        self._tk_root = None
        self._stealth_mode = False
        self._window_visible = False

    def set_progress_callback(self, callback):
        """Set progress callback for model downloads."""
        self._progress_callback = callback

    def _show_progress_window(self, message: str = "Inicjalizacja..."):
        """Show progress window for model downloads."""
        if self._progress_window:
            return
        
        try:
            import tkinter as tk
            from tkinter import ttk
            
            if self._tk_root:
                self._progress_window = tk.Toplevel(self._tk_root)
            else:
                self._tk_root = tk.Tk()
                self._progress_window = self._tk_root
            
            self._progress_window.title("Network Guardian - Pobieranie modeli")
            self._progress_window.geometry("450x200")
            self._progress_window.resizable(False, False)
            self._progress_window.eval('tk::PlaceWindow . center')
            self._progress_window.protocol("WM_DELETE_WINDOW", lambda: None)
            
            ttk.Label(self._progress_window, text="🛡 Network Guardian", font=("Segoe UI", 14, "bold")).pack(pady=15)
            
            self._progress_label = ttk.Label(self._progress_window, text=message, font=("Segoe UI", 10))
            self._progress_label.pack(pady=10)
            
            self._progress_bar = ttk.Progressbar(self._progress_window, mode='indeterminate', length=350)
            self._progress_bar.pack(pady=10)
            self._progress_bar.start(10)
            
            self._detail_label = ttk.Label(self._progress_window, text="", font=("Segoe UI", 8), foreground="gray")
            self._detail_label.pack(pady=5)
            
            self._progress_window.update()
        except Exception as e:
            logger.warning(f"Could not create progress window: {e}")
            self._progress_window = None

    def _update_progress(self, message: str, progress: float = -1):
        """Update progress window."""
        logger.info(message)
        if self._progress_window:
            try:
                self._progress_label.config(text=message)
                if progress >= 0:
                    self._progress_bar.config(mode='determinate', maximum=100, value=progress * 100)
                    self._progress_bar.stop()
                else:
                    self._progress_bar.config(mode='indeterminate')
                    self._progress_bar.start(10)
                self._detail_label.config(text=f"{progress:.0%}" if progress >= 0 else "")
                self._progress_window.update()
            except Exception:
                pass

    def _hide_progress_window(self):
        """Hide progress window."""
        if self._progress_window:
            try:
                if self._progress_window != self._tk_root:
                    self._progress_window.destroy()
                else:
                    self._progress_window.withdraw()
            except Exception:
                pass
            self._progress_window = None

    def initialize(self) -> bool:
        """Initialize all components. Returns True if successful."""
        logger.info("=" * 60)
        logger.info("🛡 NETWORK GUARDIAN - INICJALIZACJA")
        logger.info("=" * 60)

        # Show progress window for downloads
        self._show_progress_window("Sprawdzanie konfiguracji...")

        # 1. First-run setup if needed
        if self.config.is_first_run():
            logger.info("🔧 Pierwsze uruchomienie - konfiguracja...")
            self._update_progress("Konfiguracja pierwszego uruchomienia...", -1)
            
            success = run_first_run_setup(self.config)
            if not success:
                logger.error("❌ Konfiguracja anulowana lub nieudana")
                self._hide_progress_window()
                return False
            
            logger.info("✅ Konfiguracja zapisana")
        
        # Apply stealth mode settings
        stealth_cfg = self.config.get_stealth_config() if hasattr(self.config, 'get_stealth_config') else {}
        self._stealth_mode = stealth_cfg.get('enabled', True)

        # 2. Download models if needed
        model_dir = self.app_dir / "models"
        model_dir.mkdir(exist_ok=True)
        
        required_models = [
            "rf_anomaly_model.pkl",
            "scaler.pkl",
            "label_encoders.pkl",
            "feature_names.pkl"
        ]
        
        models_missing = any(not (model_dir / m).exists() for m in required_models)
        
        if models_missing or self.config.get("model.auto_download", True):
            logger.info("📥 Pobieranie modeli ML...")
            self._update_progress("Pobieranie modeli ML...", -1)
            
            upgrade_cfg = self.config.get_upgrade_config()
            self.upgrader = create_auto_upgrader(
                manifest_url=upgrade_cfg['manifest_url'],
                model_dir=str(model_dir),
                current_app_version="1.0.0",
                on_upgrade=self._on_model_upgrade,
                on_progress=self._update_progress,
                check_interval_hours=upgrade_cfg['check_interval_hours'],
                enabled=upgrade_cfg['enabled']
            )
            
            success = self.upgrader.download_initial_models(progress_callback=self._update_progress)
            if not success:
                logger.error("❌ Nie udało się pobrać modeli")
                self._hide_progress_window()
                return False
            
            logger.info("✅ Modele pobrane pomyślnie")
        else:
            logger.info("✅ Modele już istnieją")
            upgrade_cfg = self.config.get_upgrade_config()
            self.upgrader = create_auto_upgrader(
                manifest_url=upgrade_cfg['manifest_url'],
                model_dir=str(model_dir),
                current_app_version="1.0.0",
                on_upgrade=self._on_model_upgrade,
                check_interval_hours=upgrade_cfg['check_interval_hours'],
                enabled=upgrade_cfg['enabled']
            )
        
        self._hide_progress_window()
        
        # 3. Load ML models
        logger.info("📦 Ładowanie modeli ML...")
        self.engine = create_inference_engine(
            model_dir=str(model_dir),
            threshold=self.config.get("model.threshold", 0.6)
        )
        
        # 4. Setup alert manager
        logger.info("🔔 Inicjalizacja systemu alertów...")
        alerts_cfg = self.config.get_alerts_config()
        telegram_cfg = self.config.get_telegram_config()
        
        self.alert_mgr = create_alert_manager(
            telegram_bot_token=telegram_cfg.get('bot_token', ''),
            telegram_chat_id=telegram_cfg.get('chat_id', ''),
            enable_telegram=telegram_cfg.get('enabled', False) and bool(telegram_cfg.get('bot_token')),
            enable_toast=alerts_cfg.get('enable_windows_toast', True),
            cooldown_seconds=alerts_cfg.get('cooldown_seconds', 60),
            min_confidence=alerts_cfg.get('min_confidence', 0.6)
        )
        
        # Test Telegram connection
        if self.alert_mgr.telegram:
            if self.alert_mgr.telegram.test_connection():
                logger.info("✅ Telegram bot połączony")
            else:
                logger.warning("⚠️ Test Telegram nieudany - sprawdź token i chat_id")
        
        # 5. Initialize actionable toast manager
        logger.info("🔔 Inicjalizacja systemu powiadomień z akcjami...")
        self.toast_mgr = create_toast_manager(enable_actions=True)
        
        # 6. Initialize firewall manager
        logger.info("🛡 Inicjalizacja firewalla...")
        self.firewall = create_firewall_manager(dry_run=False)
        
        # 7. Initialize toast action handler
        self.toast_handler = ToastActionHandler(
            firewall_manager=self.firewall,
            whitelist_manager=self.firewall,
            settings_callback=self._open_settings_dialog
        )
        
        # Register toast action handlers
        if self.toast_mgr:
            self.toast_mgr.register_action_handler("quarantine", self.toast_handler.handle_quarantine)
            self.toast_mgr.register_action_handler("whitelist", self.toast_handler.handle_whitelist)
            self.toast_mgr.register_action_handler("dismiss", self.toast_handler.handle_dismiss)
            self.toast_mgr.register_action_handler("settings", self.toast_handler.handle_settings)
        
        # 8. Setup alert manager with actionable toasts
        if self.toast_mgr and self.alert_mgr:
            self.alert_mgr.set_toast_manager(self.toast_mgr)
        
        # 8. Initialize system tray
        logger.info("🔔 Inicjalizacja zasobnika systemowego...")
        self.tray = create_tray_manager(
            app_name="Network Guardian",
            icon_path="src/icon.ico",
            on_show_window=self._show_main_window,
            on_hide_window=self._hide_main_window,
            on_settings=self._open_settings_dialog,
            on_quarantine_ip=self._tray_quarantine_ip,
            on_whitelist_ip=self._tray_whitelist_ip,
            on_exit=self._shutdown,
            get_recent_alerts=lambda n: self.alert_mgr.get_recent_alerts(n) if self.alert_mgr else []
        )
        
        if self.tray:
            self.tray.start()
            logger.info("✅ Zasobnik systemowy uruchomiony")
        
        # 5. Start auto-upgrader for periodic checks
        if self.upgrader and self.config.get_upgrade_config().get('enabled', True):
            logger.info("🔄 Uruchamianie auto-upgrader...")
            self.upgrader.start()
        
        # 9. Start flow capture
        logger.info("🌐 Uruchamianie przechwytywania ruchu sieciowego...")
        net_cfg = self.config.get_network_config()
        self.capture = create_capture(
            interface=net_cfg.get('interface', 'auto'),
            callback=self._process_flow,
            bpf_filter=net_cfg.get('bpf_filter') if net_cfg.get('bpf_filter') else None,
            idle_timeout=net_cfg.get('idle_timeout', 120),
            active_timeout=1800,
            enable_connection_tracking=net_cfg.get('enable_connection_tracking', True),
            tracking_window=120,
            statistical=True,
            n_dissections=20
        )
        
        # Load ML models
        logger.info("📦 Ładowanie modeli ML...")
        model_dir = self.app_dir / "models"
        self.engine = create_inference_engine(
            model_dir=str(self.app_dir / "models"),
            threshold=self.config.get("model.threshold", 0.6)
        )
        
        # 6. Start auto-upgrader for periodic checks
        if self.upgrader and self.config.get_upgrade_config().get('enabled', True):
            logger.info("🔄 Uruchamianie auto-upgrader...")
            self.upgrader.start()
        
        # 10. Start flow capture
        logger.info("🌐 Uruchamianie przechwytywania ruchu sieciowego...")
        net_cfg = self.config.get_network_config()
        self.capture = create_capture(
            interface=net_cfg.get('interface', 'auto'),
            callback=self._process_flow,
            bpf_filter=net_cfg.get('bpf_filter') if net_cfg.get('bpf_filter') else None,
            idle_timeout=net_cfg.get('idle_timeout', 120),
            active_timeout=1800,
            enable_connection_tracking=net_cfg.get('enable_connection_tracking', True),
            tracking_window=120,
            statistical=True,
            n_dissections=20
        )
        
        self.running = True
        self.stats['start_time'] = time.time()
        self.capture.start()
        
        logger.info("=" * 60)
        logger.info("✅ NETWORK GUARDIAN URUCHOMIONY")
        if self._stealth_mode:
            logger.info("🥷 Tryb Stealth: UKRYTY (tylko ikona w zasobniku)")
        else:
            logger.info("   Naciśnij Ctrl+C aby zatrzymać")
        logger.info("=" * 60)
        
        return True

    def _process_flow(self, flow: dict):
        """Process a single network flow through the ML pipeline."""
        if not self.running:
            return
        
        self.stats['flows_processed'] += 1
        self.stats['last_flow_time'] = time.time()
        
        # ML Inference
        try:
            from inference_engine import PredictionResult
            prediction: PredictionResult = self.engine.predict(flow)
        except Exception as e:
            logger.error(f"Błąd inferencji: {e}")
            return
        
        # Alert if anomaly
        if prediction.is_anomaly:
            self.stats['anomalies_detected'] += 1
            if self.alert_mgr.alert(prediction):
                self.stats['alerts_sent'] += 1
    
    def _on_model_upgrade(self, new_version: str):
        """Callback when models are upgraded."""
        logger.info(f"🔄 Model zaktualizowany do v{new_version}, ponowne ładowanie...")
        try:
            model_dir = self.app_dir / "models"
            self.engine = create_inference_engine(
                model_dir=str(model_dir),
                threshold=self.config.get("model.threshold", 0.6)
            )
            
            if self.alert_mgr.telegram:
                self.alert_mgr.telegram.send_telegram(
                    f"✅ <b>Model zaktualizowany</b> do wersji <code>v{new_version}</code>"
                )
            logger.info(f"✅ Modele przeładowane pomyślnie")
        except Exception as e:
            logger.error(f"❌ Błąd przeładowania modeli: {e}")
    
    def _show_main_window(self):
        """Show main window (if not in stealth mode)."""
        self._window_visible = True
        logger.info("👁 Okno główne pokazane")

    def _hide_main_window(self):
        """Hide main window."""
        self._window_visible = False
        logger.info("🙈 Okno główne ukryte")

    def _open_settings_dialog(self):
        """Open settings dialog."""
        try:
            from settings_dialog import SettingsDialog
            dialog = SettingsDialog(
                config=self.config,
                on_save=self._on_settings_saved,
                parent=self._tk_root
            )
            dialog.show()
        except Exception as e:
            logger.error(f"Błąd otwierania ustawień: {e}")

    def _on_settings_saved(self):
        """Callback when settings are saved."""
        logger.info("💾 Ustawienia zapisane, stosowanie zmian...")
        # Reload configs that might have changed
        alerts_cfg = self.config.get_alerts_config()
        telegram_cfg = self.config.get_telegram_config()
        
        if self.alert_mgr:
            self.alert_mgr.update_config(
                telegram_bot_token=telegram_cfg.get('bot_token', ''),
                telegram_chat_id=telegram_cfg.get('chat_id', ''),
                enable_telegram=telegram_cfg.get('enabled', False),
                enable_toast=alerts_cfg.get('enable_windows_toast', True),
                cooldown_seconds=alerts_cfg.get('cooldown_seconds', 60),
                min_confidence=alerts_cfg.get('min_confidence', 0.6)
            )
        
        # Restart auto-upgrader if interval changed
        if self.upgrader:
            upgrade_cfg = self.config.get_upgrade_config()
            if self.upgrader.check_interval_hours != upgrade_cfg['check_interval_hours']:
                self.upgrader.stop()
                self.upgrader = create_auto_upgrader(
                    manifest_url=upgrade_cfg['manifest_url'],
                    model_dir=str(self.app_dir / "models"),
                    current_app_version="1.0.0",
                    on_upgrade=self._on_model_upgrade,
                    check_interval_hours=upgrade_cfg['check_interval_hours'],
                    enabled=upgrade_cfg['enabled']
                )
                self.upgrader.start()
        
        logger.info("✅ Ustawienia zastosowane")

    def _tray_quarantine_ip(self, ip: str):
        """Handle quarantine IP from tray menu."""
        if self.firewall:
            if self.firewall.block_ip(ip, "Manual quarantine from tray"):
                logger.info(f"🛡 Kwarantanna IP {ip} z zasobnika")
                if self.toast_mgr:
                    self.toast_mgr.show_test_toast()  # Quick confirmation
            else:
                logger.error(f"❌ Nie udało się zakwarantannować {ip}")

    def _tray_whitelist_ip(self, ip: str):
        """Handle whitelist IP from tray menu."""
        if self.firewall:
            if self.firewall.whitelist_ip(ip, "Manual whitelist from tray"):
                logger.info(f"✅ Dodano do białej listy {ip} z zasobnika")
            else:
                logger.error(f"❌ Nie udało się dodać do białej listy {ip}")

    def run(self):
        """Main loop - periodic stats logging."""
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)
        
        last_stats_time = time.time()
        
        try:
            while self.running:
                time.sleep(10)
                
                # Print stats every 60 seconds
                if time.time() - last_stats_time >= 60:
                    self._print_stats()
                    last_stats_time = time.time()
                
                # Check capture health
                if self.capture and not self.capture.is_running():
                    logger.error("❌ Wątek przechwytywania przestał działać, restart...")
                    self.capture.start()
        
        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown()
    
    def _print_stats(self):
        """Print periodic statistics."""
        uptime = time.time() - self.stats['start_time']
        capture_stats = self.capture.get_stats() if self.capture else {}
        upgrader_stats = self.upgrader.get_status() if self.upgrader else {}
        
        logger.info(
            f"📊 Stats: "
            f"flows={self.stats['flows_processed']} "
            f"anomalies={self.stats['anomalies_detected']} "
            f"alerts={self.stats['alerts_sent']} "
            f"uptime={uptime/60:.1f}min "
            f"capture_fps={capture_stats.get('flows_per_second', 0):.1f}"
        )
        
        if upgrader_stats.get('last_manifest_version'):
            logger.info(f"   Model version: {upgrader_stats['last_manifest_version']}")
        
        # Log firewall status
        if self.firewall:
            fw_status = self.firewall.get_status()
            logger.info(f"   🛡 Firewall: quarantined={fw_status['quarantined_count']}, whitelisted={fw_status['whitelisted_count']}")

    def _shutdown(self, signum=None, frame=None):
        """Graceful shutdown."""
        if not self.running:
            return
        
        logger.info("\n" + "=" * 60)
        logger.info("🛑 ZATRZYMYWANIE NETWORK GUARDIAN")
        logger.info("=" * 60)
        
        self.running = False
        
        # Stop components
        if self.capture:
            logger.info("Zatrzymywanie przechwytywania...")
            self.capture.stop()
        
        if self.upgrader:
            logger.info("Zatrzymywanie auto-upgrader...")
            self.upgrader.stop()
        
        if self.tray:
            logger.info("Zatrzymywanie zasobnika systemowego...")
            self.tray.stop()
        
        if self._progress_window:
            try:
                self._progress_window.destroy()
            except Exception:
                pass
        
        if self._tk_root:
            try:
                self._tk_root.destroy()
            except Exception:
                pass
        
        # Final stats
        self._print_stats()
        
        logger.info("✅ Zatrzymano pomyślnie")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Network Guardian - Portable ML Network Anomaly Detector")
    parser.add_argument("--config-dir", help="Katalog konfiguracji (domyślnie katalog .exe)")
    parser.add_argument("--no-gui", action="store_true", help="Wyłącz GUI (tryb konsoli)")
    parser.add_argument("--test-alert", action="store_true", help="Wyślij testowy alert")
    parser.add_argument("--version", action="store_true", help="Wypisz wersję")
    parser.add_argument("--force-download", action="store_true", help="Wymuś ponowne pobranie modeli")
    args = parser.parse_args()
    
    if args.version:
        print("Network Guardian v1.0.0 (Portable)")
        return
    
    # Initialize portable config
    config_dir = Path(args.config_dir) if args.config_dir else None
    config = PortableConfig(config_dir)
    
    # Force download if requested
    if args.force_download:
        import shutil
        model_dir = config.app_dir / "models"
        if model_dir.exists():
            shutil.rmtree(model_dir)
        config.set("model.auto_download", True)
    
    # Create app
    app = NetworkGuardian(config)
    
    if args.test_alert:
        # Quick test without full startup
        logger.info("🧪 Test alertu...")
        alerts_cfg = config.get_alerts_config()
        telegram_cfg = config.get_telegram_config()
        
        alert_mgr = create_alert_manager(
            telegram_bot_token=telegram_cfg.get('bot_token', ''),
            telegram_chat_id=telegram_cfg.get('chat_id', ''),
            enable_telegram=telegram_cfg.get('enabled', False) and bool(telegram_cfg.get('bot_token')),
            enable_toast=alerts_cfg.get('enable_windows_toast', True)
        )
        
        if alert_mgr.send_test_alert():
            logger.info("✅ Test alertu wysłany")
        else:
            logger.error("❌ Test alertu nieudany")
        return
    
    # Initialize and run
    if app.initialize():
        app.run()
    else:
        logger.error("❌ Inicjalizacja nieudana")
        sys.exit(1)


if __name__ == "__main__":
    main()
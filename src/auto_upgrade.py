#!/usr/bin/env python3
"""
Task 6: Auto-Upgrade Module + First-Run Model Downloader
Checks for new model versions, downloads, verifies SHA256, and hot-swaps models.
Also handles initial model download on first run.
"""

import hashlib
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)


@dataclass
class ModelManifest:
    """Model manifest from remote source."""
    version: str
    model_url: str
    scaler_url: str
    encoders_url: str
    feature_names_url: str | None = None
    threat_classifier_url: str | None = None
    sha256_model: str = ""
    sha256_scaler: str = ""
    sha256_encoders: str = ""
    sha256_feature_names: str = ""
    sha256_threat_classifier: str = ""
    min_app_version: str = "1.0.0"
    changelog: str = ""
    released_at: str = ""
    
    @classmethod
    def from_json(cls, data: dict[str, Any]) -> 'ModelManifest':
        return cls(**data)


class ModelDownloader:
    """Handles downloading model files with progress and verification."""
    
    REQUIRED_FILES = [
        ('model', 'rf_anomaly_model.pkl'),
        ('scaler', 'scaler.pkl'),
        ('encoders', 'label_encoders.pkl'),
        ('feature_names', 'feature_names.pkl'),
    ]
    
    OPTIONAL_FILES = [
        ('threat_classifier', 'threat_classifier.pkl'),
    ]
    
    def __init__(
        self,
        model_dir: Path,
        manifest_url: str,
        progress_callback: Callable[[str, float], None] | None = None,
        max_retries: int = 3,
        retry_delay: int = 5
    ):
        self.model_dir = Path(model_dir)
        self.manifest_url = manifest_url
        self.progress_callback = progress_callback
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._stop_event = threading.Event()
        
        self.model_dir.mkdir(parents=True, exist_ok=True)
    
    def _report_progress(self, message: str, progress: float = -1):
        """Report progress to callback."""
        logger.info(message)
        if self.progress_callback:
            try:
                self.progress_callback(message, progress)
            except Exception:
                pass
    
    def download_all_models(self, manifest: ModelManifest, force: bool = False) -> bool:
        """Download all required model files from manifest."""
        self._report_progress("📥 Rozpoczynam pobieranie modeli...", 0.0)
        
        # Check if already have models
        if not force and self._check_models_exist(manifest):
            self._report_progress("✅ Modele już istnieją", 1.0)
            return True
        
        # Build download list
        downloads = []
        for key, fname in self.REQUIRED_FILES:
            url = getattr(manifest, f"{key}_url", "")
            sha256 = getattr(manifest, f"sha256_{key}", "")
            if url:
                downloads.append((key, fname, url, sha256))
        
        for key, fname in self.OPTIONAL_FILES:
            url = getattr(manifest, f"{key}_url", "")
            sha256 = getattr(manifest, f"sha256_{key}", "")
            if url:
                downloads.append((key, fname, url, sha256))
        
        if not downloads:
            self._report_progress("❌ Brak URL-i do pobrania", 1.0)
            return False
        
        # Download each file
        total = len(downloads)
        for i, (key, fname, url, expected_sha256) in enumerate(downloads):
            if self._stop_event.is_set():
                return False
            
            progress = i / total
            self._report_progress(f"📥 Pobieranie {fname} ({i+1}/{total})...", progress)
            
            tmp_path = self._download_and_verify(url, expected_sha256, fname)
            if not tmp_path:
                self._report_progress(f"❌ Błąd pobierania {fname}", progress)
                return False
            
            # Move to final location
            final_path = self.model_dir / fname
            if final_path.exists():
                final_path.unlink()
            tmp_path.rename(final_path)
            self._report_progress(f"✅ Zapisano {fname}", progress)
        
        # Write version file
        version_file = self.model_dir / "model_version.txt"
        version_file.write_text(manifest.version)
        
        self._report_progress("✅ Wszystkie modele pobrane pomyślnie", 1.0)
        return True
    
    def _check_models_exist(self, manifest: ModelManifest) -> bool:
        """Check if all required model files exist and match version."""
        version_file = self.model_dir / "model_version.txt"
        if version_file.exists():
            local_version = version_file.read_text().strip()
            if local_version == manifest.version:
                # Verify all required files exist
                for _, fname in self.REQUIRED_FILES:
                    if not (self.model_dir / fname).exists():
                        return False
                return True
        return False
    
    def _download_and_verify(self, url: str, expected_sha256: str, fname: str) -> Path | None:
        """Download single file with retries and verify SHA256."""
        tmp_path = self.model_dir / f".tmp_{fname}"
        
        for attempt in range(self.max_retries):
            if self._stop_event.is_set():
                return None
            
            try:
                self._report_progress(f"  Pobieranie {fname} (próba {attempt + 1}/{self.max_retries})...")
                
                resp = requests.get(url, timeout=120, stream=True)
                resp.raise_for_status()
                
                hasher = hashlib.sha256()
                total_size = int(resp.headers.get('content-length', 0))
                downloaded = 0
                
                with open(tmp_path, 'wb') as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        if self._stop_event.is_set():
                            return None
                        if chunk:
                            f.write(chunk)
                            hasher.update(chunk)
                            downloaded += len(chunk)
                            
                            # Report progress
                            if total_size > 0:
                                pct = downloaded / total_size
                                self._report_progress(f"  {fname}: {pct:.0%}", -1)
                
                # Verify hash
                actual_sha256 = hasher.hexdigest()
                if expected_sha256 and actual_sha256 != expected_sha256:
                    self._report_progress(f"  ❌ SHA256 mismatch dla {fname}")
                    tmp_path.unlink(missing_ok=True)
                    return None
                
                self._report_progress(f"  ✅ {fname} zweryfikowano (SHA256: {actual_sha256[:16]}...)")
                return tmp_path
                
            except Exception as e:
                self._report_progress(f"  ⚠️ Próba {attempt + 1} nieudana: {e}")
                if tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
        
        self._report_progress(f"  ❌ Wszystkie próby pobierania {fname} nieudane")
        return None
    
    def stop(self):
        """Stop downloader."""
        self._stop_event.set()


class AutoUpgrader:
    """
    Automatic model upgrader.
    Checks manifest URL periodically, downloads new models, verifies integrity, hot-swaps.
    """
    
    def __init__(
        self,
        manifest_url: str,
        model_dir: Path,
        current_app_version: str = "1.0.0",
        on_upgrade: Callable[[str], None] | None = None,
        on_progress: Callable[[str, float], None] | None = None,
        check_interval_hours: int = 6,
        max_retries: int = 3,
        retry_delay: int = 60
    ):
        self.manifest_url = manifest_url
        self.model_dir = Path(model_dir)
        self.current_app_version = current_app_version
        self.on_upgrade = on_upgrade
        self.check_interval_hours = check_interval_hours
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_check: datetime | None = None
        self._last_manifest: ModelManifest | None = None
        self._upgrade_in_progress = False
        
        # Model downloader
        self.downloader = ModelDownloader(
            model_dir=self.model_dir,
            manifest_url=manifest_url,
            progress_callback=on_progress,
            max_retries=max_retries,
            retry_delay=retry_delay
        )
        
        # Ensure model directory exists
        self.model_dir.mkdir(parents=True, exist_ok=True)
    
    def start(self):
        """Start background upgrade checker."""
        if self._thread and self._thread.is_alive():
            logger.warning("Auto-upgrader already running")
            return
        
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="AutoUpgrader"
        )
        self._thread.start()
        logger.info(f"🔄 Auto-upgrader started (check every {self.check_interval_hours}h)")
        
        # Initial check (non-blocking)
        threading.Thread(target=self.check_and_upgrade, daemon=True).start()
    
    def stop(self, timeout: float = 10.0):
        """Stop background checker."""
        logger.info("🛑 Stopping auto-upgrader...")
        self._stop_event.set()
        self.downloader.stop()
        if self._thread:
            self._thread.join(timeout=timeout)
        logger.info("✅ Auto-upgrader stopped")
    
    def _run_loop(self):
        """Main loop - periodic checks."""
        while not self._stop_event.is_set():
            # Sleep in small chunks to allow quick shutdown
            sleep_seconds = self.check_interval_hours * 3600
            chunk = 60  # Check stop event every minute
            slept = 0
            
            while slept < sleep_seconds and not self._stop_event.is_set():
                time.sleep(min(chunk, sleep_seconds - slept))
                slept += chunk
            
            if not self._stop_event.is_set():
                try:
                    self.check_and_upgrade()
                except Exception as e:
                    logger.error(f"Auto-upgrade check failed: {e}")
    
    def check_and_upgrade(self, force: bool = False) -> bool:
        """
        Check for new model version and upgrade if available.
        
        Args:
            force: Force upgrade even if version same
            
        Returns:
            bool: True if upgrade performed
        """
        if self._upgrade_in_progress:
            logger.warning("Upgrade already in progress, skipping")
            return False
        
        self._upgrade_in_progress = True
        try:
            # Fetch manifest
            logger.info(f"🔍 Checking for model updates: {self.manifest_url}")
            manifest = self._fetch_manifest()
            if not manifest:
                return False
            
            self._last_check = datetime.now()
            self._last_manifest = manifest
            
            # Check version
            if not force and not self._is_newer_version(manifest.version):
                logger.info(f"✅ Model up to date (v{manifest.version})")
                return False
            
            # Check app version compatibility
            if not self._is_compatible(manifest.min_app_version):
                logger.warning(
                    f"⚠️ Model v{manifest.version} requires app v{manifest.min_app_version}, "
                    f"current: v{self.current_app_version}"
                )
                return False
            
            # Download and verify all files
            logger.info(f"⬇️ Downloading model v{manifest.version}...")
            if not self.downloader.download_all_models(manifest):
                logger.error("❌ Download/verification failed")
                return False
            
            # Reload models callback
            if self.on_upgrade:
                try:
                    self.on_upgrade(manifest.version)
                except Exception as e:
                    logger.error(f"on_upgrade callback failed: {e}")
            
            logger.info(f"✅ Model upgraded to v{manifest.version}")
            return True
            
        finally:
            self._upgrade_in_progress = False
    
    def _fetch_manifest(self) -> ModelManifest | None:
        """Fetch and parse model manifest."""
        try:
            resp = requests.get(self.manifest_url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return ModelManifest.from_json(data)
        except Exception as e:
            logger.error(f"Failed to fetch manifest: {e}")
            return None
    
    def _is_newer_version(self, remote_version: str) -> bool:
        """Compare version strings (semver)."""
        def parse(v: str):
            v = v.lstrip('v')
            parts = v.split('.')
            return tuple(int(p) for p in parts)
        
        # Check local version
        version_file = self.model_dir / "model_version.txt"
        local_version = "0.0.0"
        if version_file.exists():
            local_version = version_file.read_text().strip().lstrip('v')
        
        try:
            return parse(remote_version) > parse(local_version)
        except Exception:
            return True  # Assume newer if parsing fails
    
    def _is_compatible(self, min_app_version: str) -> bool:
        """Check if current app version meets minimum."""
        def parse(v: str):
            v = v.lstrip('v')
            parts = v.split('.')
            return tuple(int(p) for p in parts)
        
        try:
            return parse(self.current_app_version) >= parse(min_app_version)
        except Exception:
            return True
    
    def get_status(self) -> dict[str, Any]:
        """Get upgrader status."""
        return {
            'running': self._thread is not None and self._thread.is_alive(),
            'last_check': self._last_check.isoformat() if self._last_check else None,
            'last_manifest_version': self._last_manifest.version if self._last_manifest else None,
            'check_interval_hours': self.check_interval_hours,
            'upgrade_in_progress': self._upgrade_in_progress,
            'model_dir': str(self.model_dir),
            'current_app_version': self.current_app_version,
        }
    
    def force_check(self) -> bool:
        """Force an immediate upgrade check."""
        return self.check_and_upgrade(force=True)
    
    def download_initial_models(self, progress_callback: Callable | None = None) -> bool:
        """Download models on first run."""
        logger.info("📥 Pierwsze uruchomienie - pobieranie modeli...")
        
        # Fetch manifest
        manifest = self._fetch_manifest()
        if not manifest:
            logger.error("❌ Nie można pobrać manifestu")
            return False
        
        # Use downloader with custom progress callback
        downloader = ModelDownloader(
            model_dir=self.model_dir,
            manifest_url=self.manifest_url,
            progress_callback=progress_callback,
            max_retries=self.max_retries,
            retry_delay=self.retry_delay
        )
        
        return downloader.download_all_models(manifest)


def create_auto_upgrader(
    manifest_url: str,
    model_dir: str,
    **kwargs
) -> AutoUpgrader:
    """Factory function to create auto upgrader."""
    return AutoUpgrader(
        manifest_url=manifest_url,
        model_dir=Path(model_dir),
        **kwargs
    )


if __name__ == "__main__":
    # Test
    import logging
    logging.basicConfig(level=logging.INFO)
    
    def progress(msg, pct):
        print(f"[{pct:.0%}] {msg}" if pct >= 0 else f"  {msg}")
    
    def on_upgrade(version):
        print(f"🔄 Model zaktualizowany do v{version}")
    
    upgrader = create_auto_upgrader(
        manifest_url="https://raw.githubusercontent.com/kstanisz88/anomaly-detector/main/model_manifest.json",
        model_dir="./models",
        on_upgrade=on_upgrade,
        on_progress=progress,
        check_interval_hours=6
    )
    
    # Test initial download
    success = upgrader.download_initial_models(progress_callback=progress)
    print(f"Download result: {success}")
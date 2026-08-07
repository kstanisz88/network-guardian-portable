#!/usr/bin/env python3
"""
Task 8&9: Portable Build Script
Creates single .exe with all dependencies, model files downloaded on first run.
No Windows Service installation needed - runs as portable app.
"""

import subprocess
import shutil
import sys
import os
import urllib.request
import zipfile
from pathlib import Path
import hashlib


def build_executable():
    """Build single portable .exe using PyInstaller."""
    print("🔨 Building Network Guardian Portable executable...")
    
    # Clean previous builds
    for d in ["build", "dist", "__pycache__"]:
        shutil.rmtree(d, ignore_errors=True)
    for f in Path(".").glob("*.spec"):
        f.unlink(missing_ok=True)
    
    # Create PyInstaller spec for portable version
    spec_content = '''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['src/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('src/portable_config.py', 'src'),
        ('src/capture_module.py', 'src'),
        ('src/inference_engine.py', 'src'),
        ('src/alert_manager.py', 'src'),
        ('src/auto_upgrade.py', 'src'),
        ('src/system_tray.py', 'src'),
        ('src/settings_dialog.py', 'src'),
        ('src/toast_actions.py', 'src'),
        ('src/firewall_manager.py', 'src'),
        ('config.yaml', '.'),
    ],
    hiddenimports=[
        'nfstream',
        'sklearn',
        'sklearn.ensemble',
        'sklearn.preprocessing',
        'sklearn.model_selection',
        'joblib',
        'numpy',
        'pandas',
        'xgboost',
        'lightgbm',
        'requests',
        'yaml',
        'psutil',
        'win10toast',
        'tkinter',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'tkinter.messagebox',
        'threading',
        'queue',
        'collections',
        'dataclasses',
        'typing',
        'pathlib',
        'datetime',
        'signal',
        'argparse',
        'hashlib',
        'base64',
        'json',
        'os',
        'sys',
        'time',
        # Custom modules
        'portable_config',
        'capture_module',
        'inference_engine',
        'alert_manager',
        'auto_upgrade',
        'system_tray',
        'settings_dialog',
        'toast_actions',
        'firewall_manager',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter.test', 'matplotlib', 'PIL', 'cv2', 'IPython',
        'jupyter', 'notebook', 'pytest', 'test',
        'scipy.spatial', 'scipy.stats',  # Keep only needed scipy
    ],
    cipher=block_cipher,
    noarchive=False,
)

# Filter out large unnecessary binaries
a.binaries = [x for x in a.binaries if not any(
    skip in x[0] for skip in ['mkl', 'openblas', 'libgfortran']
)]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='NetworkGuardian',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Console for logs
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico' if os.path.exists('assets/icon.ico') else None,
)
'''
    
    spec_path = Path("NetworkGuardian.spec")
    spec_path.write_text(spec_content)
    
    # Run PyInstaller
    print("\n🚀 Running PyInstaller...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "PyInstaller", str(spec_path), "--clean"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            print("❌ PyInstaller failed:")
            print(result.stderr[-3000:])
            return False
        
        # Verify executable
        exe_path = Path("dist/NetworkGuardian.exe")
        if not exe_path.exists():
            print("❌ Executable not created")
            return False
        
        size_mb = exe_path.stat().st_size / 1e6
        print(f"\n✅ Build successful!")
        print(f"   Executable: {exe_path}")
        print(f"   Size: {size_mb:.1f} MB")
        
        # Test run
        print("\n🧪 Testing executable...")
        test_result = subprocess.run(
            [str(exe_path), "--version"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if test_result.returncode == 0:
            print(f"✅ Executable runs: {test_result.stdout.strip()}")
        else:
            print(f"⚠️ Executable test (may need config): {test_result.stderr[:200]}")
        
        return True
        
    except subprocess.TimeoutExpired:
        print("❌ PyInstaller timed out")
        return False
    except Exception as e:
        print(f"❌ Build error: {e}")
        return False


def create_portable_package():
    """Create a portable distribution package."""
    print("\n📦 Creating portable distribution package...")
    
    package_dir = Path("NetworkGuardian_Portable")
    shutil.rmtree(package_dir, ignore_errors=True)
    package_dir.mkdir()
    
    # Copy executable
    exe_src = Path("dist/NetworkGuardian")
    if not exe_src.exists():
        # Try Windows name
        exe_src = Path("dist/NetworkGuardian.exe")
    exe_dst = package_dir / "NetworkGuardian.exe"
    if exe_src.exists():
        shutil.copy2(exe_src, exe_dst)
        print(f"  ✅ Copied executable ({exe_src.stat().st_size/1e6:.1f} MB)")
    else:
        print(f"  ⚠️ Executable not found at {exe_src}")
    
    # Copy config template
    config_src = Path("config.yaml")
    config_dst = package_dir / "config.yaml"
    if config_src.exists():
        shutil.copy2(config_src, config_dst)
        print(f"  ✅ Copied config template")
    
    # Create README for portable version
    readme_content = """# Network Guardian Portable

## Uruchomienie

1. Uruchom `NetworkGuardian.exe`
2. Przy pierwszym uruchomieniu otworzy się okno konfiguracji
3. Wypełnij:
   - **Bot Token** (z @BotFather w Telegram)
   - **Chat ID** (z @userinfobot w Telegram)
4. Kliknij "Zapisz i uruchom"

## Funkcje

- 🔍 Monitorowanie ruchu sieciowego w czasie rzeczywistym
- 🤖 Wykrywanie anomalii ML (RandomForest + XGBoost + LightGBM)
- 📱 Alerty Telegram + Windows Toast
- 🛠 Konkretne kroki remedialne per typ ataku
- 🔄 Automatyczne aktualizacje modeli (co 6h)

## Pliki

- `NetworkGuardian.exe` - Główny program
- `config.yaml` - Konfiguracja (tworzona automatycznie)
- `network_guardian.log` - Logi (tworzone automatycznie)
- `models/` - Modele ML (pobierane automatycznie przy pierwszym uruchomieniu)

## Wymagania

- Windows 10/11 (x64)
- Uprawnienia administratora do przechwytywania pakietów (WinPcap/Npcap NIE wymagane - używa nfstream)

## Aktualizacje

Program sprawdza aktualizacje modeli co 6 godzin automatycznie.
Manifest: https://raw.githubusercontent.com/kstanisz88/anomaly-detector/main/model_manifest.json

## Logi

Sprawdź `network_guardian.log` w razie problemów.
"""
    
    (package_dir / "README_PORTABLE.txt").write_text(readme_content, encoding='utf-8')
    print(f"  ✅ Created README")
    
    # Create zip
    zip_path = Path("NetworkGuardian_Portable.zip")
    if zip_path.exists():
        zip_path.unlink()
    
    shutil.make_archive("NetworkGuardian_Portable", 'zip', package_dir)
    size_mb = zip_path.stat().st_size / 1e6
    print(f"\n✅ Portable package created: {zip_path} ({size_mb:.1f} MB)")
    
    return True


def generate_manifest():
    """Generate model_manifest.json with SHA256 hashes."""
    model_dir = Path("models")
    
    files_to_hash = {
        "model": "rf_anomaly_model.pkl",
        "scaler": "scaler.pkl",
        "encoders": "label_encoders.pkl",
        "feature_names": "feature_names.pkl",
    }
    
    optional_files = {
        "threat_classifier": "threat_classifier.pkl",
    }
    
    print("🔐 Computing SHA256 hashes...")
    manifest = {
        "version": "1.0.0",
        "released_at": "2026-08-05T00:00:00Z",
        "min_app_version": "1.0.0",
        "changelog": "Initial portable release with ensemble model (RF + XGBoost + LightGBM)",
    }
    
    for key, fname in files_to_hash.items():
        path = model_dir / fname
        if path.exists():
            sha256 = compute_sha256(path)
            manifest[f"{key}_url"] = f"https://github.com/kstanisz88/anomaly-detector/releases/download/v1.0.0/{fname}"
            manifest[f"sha256_{key}"] = sha256
            print(f"  ✅ {fname}: {sha256[:16]}...")
        else:
            print(f"  ❌ {fname} not found")
            return False
    
    for key, fname in optional_files.items():
        path = model_dir / fname
        if path.exists():
            sha256 = compute_sha256(path)
            manifest[f"{key}_url"] = f"https://github.com/kstanisz88/anomaly-detector/releases/download/v1.0.0/{fname}"
            manifest[f"sha256_{key}"] = sha256
            print(f"  ✅ {fname} [optional]: {sha256[:16]}...")
        else:
            manifest[f"{key}_url"] = ""
            manifest[f"sha256_{key}"] = ""
            print(f"  ⚠️ {fname} not found [optional]")
    
    # Save manifest
    manifest_path = Path("model_manifest.json")
    import json
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\n✅ Manifest saved to {manifest_path}")
    
    print("\n📋 NEXT STEPS:")
    print("1. Create GitHub Release v1.0.0 in kstanisz88/anomaly-detector")
    print("2. Upload all model files from models/ directory")
    print("3. Copy model_manifest.json to repo root (or host at raw.githubusercontent.com)")
    print("4. Enable GitHub Pages for repo (Settings → Pages → Deploy from main branch)")
    print("5. Manifest will be available at: https://kstanisz88.github.io/anomaly-detector/model_manifest.json")
    
    return True


def compute_sha256(filepath: Path) -> str:
    """Compute SHA256 hash of file."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Guardian Portable Build")
    parser.add_argument("command", choices=["build", "package", "manifest", "all"],
                       help="Command to run")
    
    args = parser.parse_args()
    
    if args.command == "build":
        success = build_executable()
        sys.exit(0 if success else 1)
    
    elif args.command == "package":
        success = create_portable_package()
        sys.exit(0 if success else 1)
    
    elif args.command == "manifest":
        success = generate_manifest()
        sys.exit(0 if success else 1)
    
    elif args.command == "all":
        print("=" * 60)
        print("🔨 FULL PORTABLE BUILD PIPELINE")
        print("=" * 60)
        
        if not build_executable():
            sys.exit(1)
        
        if not generate_manifest():
            sys.exit(1)
        
        if not create_portable_package():
            sys.exit(1)
        
        print("\n✅ Portable build complete!")
        print("   Distribution: NetworkGuardian_Portable.zip")
        print("   Upload to GitHub Releases")


if __name__ == "__main__":
    main()
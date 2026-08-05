# Network Guardian Portable

## Uruchomienie

1. Uruchom `NetworkGuardian.exe`
2. Przy pierwszym uruchomieniu otworzy się okno konfiguracji
3. Wypełnij (opcjonalnie):
   - **Bot Token** (z @BotFather w Telegram)
   - **Chat ID** (z @userinfobot w Telegram)
   - Możesz **pominąć** konfigurację Telegram i ustawić później w Ustawieniach
4. Kliknij **"Zapisz i uruchom"** lub **"Pomiń konfigurację Telegram"**

## Nowe funkcje v1.0.0

- 🥷 **Tryb Stealth** - program działa w tle, tylko ikona w zasobniku systemowym
- ⏭ **Opcja "Pomiń"** - konfiguracja Telegram opcjonalna, ustawisz później w Ustawieniach
- 🔔 **Actionable Toasty** - powiadomienia Windows z przyciskami akcji:
  - 🛡 **Kwarantanna** - blokuje IP na firewallu Windows
  - ✅ **Biała lista** - dodaje IP do wyjątków firewalla
  - 🗑 **Usuń** - zamyka powiadomienie
  - ⚙️ **Ustawienia** - otwiera okno ustawień
- 🛡 **Integracja z firewallem** - automatyczna kwarantanna/whitelist IP
- 🖥 **Zasobnik systemowy** - menu: Pokaż/Ustawienia/Kwarantanna/Biała lista/Ostatnie alerty/Wyjdź
- 🔄 **Auto-upgrade** - sprawdza aktualizacje modeli co 6h z GitHub Pages

## Funkcje

- 🔍 Monitorowanie ruchu sieciowego w czasie rzeczywistym
- 🤖 Wykrywanie anomalii ML (RandomForest + XGBoost + LightGBM ensemble)
- 📱 Alerty Telegram (HTML) + Windows Toast z przyciskami akcji
- 🛠 Konkretne kroki remedialne per typ ataku (DoS, Probe, R2L, U2R, Data Exfil, C2, Phishing)
- 🔄 Automatyczne aktualizacje modeli (co 6h) z GitHub Pages + SHA256 verify
- 🥷 Tryb Stealth - ukryty w tle, tylko ikona w zasobniku

## Pliki

- `NetworkGuardian.exe` - Główny program (~259 MB)
- `config.yaml` - Szablon konfiguracji (tworzona automatycznie `network_guardian_config.json`)
- `network_guardian.log` - Logi (tworzone automatycznie)
- `models/` - Modele ML (pobierane automatycznie przy pierwszym uruchomieniu ~70 MB)

## Wymagania

- Windows 10/11 (x64)
- Uprawnienia administratora do przechwytywania pakietów (WinPcap/Npcap NIE wymagane - używa nfstream)
- Dla firewalla: uprawnienia admin do netsh advfirewall

## Aktualizacje

Program sprawdza aktualizacje modeli co 6 godzin automatycznie.
Manifest: https://raw.githubusercontent.com/kstanisz88/anomaly-detector/main/model_manifest.json

## Logi

Sprawdź `network_guardian.log` w razie problemów.

## Ustawienia (dostępne z zasobnika systemowego)

- **Ogólne**: język, motyw, autostart, minimalizuj do tray, poziom logów
- **Telegram**: włącz/wyłącz, bot token, chat ID, test połączenia
- **Alerty**: Windows Toast (z przyciskami akcji), cooldown, minimalna pewność, biała lista IP
- **Sieć**: interfejs, filtr BPF, timeouty, śledzenie połączeń
- **Model**: próg anomalii, auto-pobieranie
- **Aktualizacje**: włącz/wyłącz, interwał, URL manifestu, sprawdź teraz
- **O programie**: wersja, technologie, wykrywane zagrożenia, licencja
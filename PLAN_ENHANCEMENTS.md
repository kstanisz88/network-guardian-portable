# Plan: Network Guardian Portable - Enhanced Features

## Goals
1. Add application icon (.ico) to build
2. Implement Stealth mode (system tray, no console)
3. Add "Skip" option for Telegram config (configure later in settings)
4. Windows Toast notifications with action buttons (Quarantine/Whitelist/Delete)
5. Settings UI accessible from system tray
6. Test and generate final portable zip

---

## Technical Requirements

### 1. Icon (.ico)
- Create/generate 256x256 .ico file
- Include in PyInstaller spec
- Use for exe icon and system tray

### 2. Stealth Mode
- PyInstaller: `console=False` (no console window)
- System tray icon using `pystray` library
- Tray menu: Show/Hide Window, Settings, Quarantine IP, Whitelist IP, Exit
- Hidden by default, show window on double-click or "Show" menu

### 3. Skip Telegram Config
- First-run UI: Add "Skip" button
- If skipped: Save config with `telegram.enabled: false`
- Settings dialog: Allow configuring Telegram later
- Re-enable Telegram alerts when configured

### 4. Windows Toast with Actions
- Use `winrt` / `windows.toast` for actionable notifications
- Toast XML with buttons: "🛡 Kwarantanna", "✅ Białą listę", "🗑 Usuń", "⚙️ Ustawienia"
- Handle button clicks via callback registration
- Actions: Quarantine IP (block in firewall), Whitelist IP, Delete alert, Open settings

### 5. Settings UI
- Accessible from tray menu "Ustawienia"
- Tabs: Ogólne, Telegram, Alerty, Sieć, Aktualizacje
- Live preview of Telegram connection
- Save/Load config

---

## Implementation Plan

### Phase 1: Core Infrastructure
- [ ] Create app icon (generate .ico)
- [ ] Add pystray dependency
- [ ] Update PyInstaller spec (console=False, icon, hidden imports)
- [ ] Create system tray manager class

### Phase 2: Stealth Mode & Tray
- [ ] SystemTrayManager class with menu
- [ ] Toggle window visibility
- [ ] Handle tray events (double-click, right-click)
- [ ] Graceful shutdown from tray

### Phase 3: Enhanced First-Run UI
- [ ] Add "Pomiń" (Skip) button to FirstRunSetupUI
- [ ] Handle skipped Telegram config
- [ ] Show info that Telegram can be configured later

### Phase 4: Settings Dialog
- [ ] SettingsDialog class (tkinter)
- [ ] Tabbed interface
- [ ] Load/save config
- [ ] Telegram test connection

### Phase 5: Actionable Toast Notifications
- [ ] Windows Toast with action buttons (using winrt)
- [ ] Register COM activator for button clicks
- [ ] Implement action handlers:
  - Quarantine IP → Windows Firewall block rule
  - Whitelist IP → Add to config whitelist
  - Delete → Dismiss alert
  - Settings → Open settings dialog

### Phase 6: Integration & Testing
- [ ] Wire all components in main.py
- [ ] Test stealth mode
- [ ] Test toast actions
- [ ] Test settings persistence
- [ ] Build final executable
- [ ] Generate portable zip

---

## Dependencies to Add
- `pystray` - System tray icon
- `pillow` - Image handling for tray icon
- `winrt` - Windows Runtime for actionable toasts (Windows 10+)
- `comtypes` - COM interface for toast activation

---

## File Changes

### New Files
- `src/icon.ico` - Application icon
- `src/system_tray.py` - SystemTrayManager
- `src/settings_dialog.py` - SettingsDialog
- `src/toast_actions.py` - ActionableToastManager
- `src/firewall_manager.py` - FirewallManager (quarantine/whitelist)

### Modified Files
- `src/portable_config.py` - Add skip option
- `src/main.py` - Integrate tray, stealth mode, settings
- `src/alert_manager.py` - Add actionable toasts
- `build.py` - Update spec for icon, console=False, new imports
- `requirements.txt` - Add new dependencies

---

## Testing Checklist
- [ ] First-run UI with Skip works
- [ ] Stealth mode: no console, tray icon appears
- [ ] Tray menu: Show, Settings, Quarantine, Whitelist, Exit
- [ ] Settings dialog opens from tray
- [ ] Telegram config in settings works
- [ ] Toast notification appears with action buttons
- [ ] Clicking "Kwarantanna" blocks IP in firewall
- [ ] Clicking "Biała lista" adds IP to whitelist
- [ ] Clicking "Ustawienia" opens settings dialog
- [ ] Config persists across restarts
- [ ] Build succeeds with icon
- [ ] Portable zip generated
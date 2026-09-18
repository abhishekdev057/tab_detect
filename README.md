# 🛡️ SentinelTab - Browser Tab Switch & Activity Detection System

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/abhishekdev057/tab_detect)

A high-tech, real-time proctoring and browser vigilance dashboard built with HTML5, Vanilla CSS, and JavaScript. It monitors, penalizes, and logs unauthorized candidate actions during online tests, exams, or sensitive sessions.

---

## ⚡ 1-Click Vercel Deployment

Deploy your own live copy instantly to Vercel:

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/abhishekdev057/tab_detect)

### Manual Vercel Deployment (via Vercel Dashboard):
1. Go to [vercel.com/new](https://vercel.com/new).
2. Connect your GitHub account and select repository: **`abhishekdev057/tab_detect`**.
3. Framework Preset: **Other** (Static Site - zero configuration needed).
4. Click **Deploy**. Your site will be live on a `*.vercel.app` URL within seconds!

---

## 🚀 Key Detection Vectors

1. **Tab Switch & Visibility Detection (`document.visibilitychange`)**
   - Detects when the candidate switches to another browser tab or minimizes the browser.
   - Measures exact duration away in milliseconds and logs timestamps.
   - Triggers audio alarm, visual threat flash, violation modal, and strike penalty.

2. **Window Blur & Application Switch (`window.blur`)**
   - Detects when the candidate clicks outside the browser (e.g. Discord, WhatsApp, Telegram, terminal, split-screen note apps, or a second monitor).

3. **Fullscreen Compliance & Esc Lockout**
   - Enforces Fullscreen mode and detects if the user presses `Esc` to restore or exit window.

4. **Mouse Viewport Departure (`mouseleave`)**
   - Warns when the user moves the cursor up towards browser tabs or the URL search bar.

5. **Keyboard Shortcut Shield & Clipboard Protection**
   - Blocks prohibited shortcuts: `F12`, `Ctrl+Shift+I` (Inspect), `Ctrl+C` (Copy), `Ctrl+V` (Paste), `Ctrl+X` (Cut), `Ctrl+U` (View Source), `PrintScreen`.
   - Flags `Alt` key clicks (potential `Alt+Tab` attempts).
   - Restricts right-click context menu.

6. **DevTools Trap**
   - Heuristic detection based on inner vs. outer window dimensions.

7. **Proctoring HUD & Webcam Integration**
   - Camera access preview with facial tracking reticle and AI surveillance scanlines.
   - Built-in simulation fallback if no camera hardware is attached.

8. **Integrity Score Gauge & 3-Strike System**
   - Dynamic trust score from 100% down to 0% with SVG circular meter.
   - 3 strikes trigger a full-screen **Disqualification / Lockout Screen**.

9. **Security Audit Trail & JSON Export**
   - Chronological log of all events with severity badges (`CRITICAL`, `WARNING`, `INFO`).
   - One-click export to download a timestamped `sentinel_audit_report.json`.

---

## 💻 How to Run Locally

You can run this project locally with any static web server:

### Option 1: Using Node / npx
```bash
npx serve . -p 3000
```
Then open: [http://localhost:3000](http://localhost:3000)

### Option 2: Using Python
```bash
python3 -m http.server 3000
```
Then open: [http://localhost:3000](http://localhost:3000)

---

## 🧪 How to Test the Detections

1. **Test Tab Switch**:
   - Open a new tab in your browser (`Ctrl+T` or `Cmd+T`) or click on any other open tab.
   - Stay there for 3-5 seconds, then return to SentinelTab.
   - **Result**: Immediate red alert modal pops up showing the exact seconds you spent away, alarm siren sounds, strike counter increments (1/3), and candidate trust score decreases.

2. **Test Window Blur**:
   - Click outside the browser window (e.g., click on your desktop or another open application like Notes or Terminal).
   - **Result**: Yellow warning toast pops up: *"Window Focus Lost! Please keep attention focused inside assessment."*

3. **Test Prohibited Keys**:
   - Try pressing `Ctrl+C` or `Cmd+C` or right-clicking anywhere in the question area.
   - **Result**: Action blocked, strike recorded in the live audit log.

4. **Test Fullscreen Enforcement**:
   - Click the "Fullscreen" button in the top bar.
   - Press `Esc`.
   - **Result**: Critical alert logged, strike incremented.

5. **Test Disqualification Lockout**:
   - Accumulate 3 strikes (switch tabs 3 times).
   - **Result**: The entire test locks down with a red lockdown screen requiring administrator reset or audit log download.

/**
 * SentinelTab - Proctoring & Tab Switch Detection Engine
 * Real-time monitoring of tab switching, window blurs, shortcuts, mouse leave, and full-screen compliance.
 */

(() => {
  'use strict';

  // ==========================================================================
  // Application State
  // ==========================================================================
  const state = {
    startTime: Date.now(),
    timerInterval: null,
    integrityScore: 100,
    strikes: 0,
    maxStrikes: 3,
    tabSwitches: 0,
    windowBlurs: 0,
    shortcutAttempts: 0,
    totalTimeAwayMs: 0,
    
    // Away detection state
    isAway: false,
    awayStartTimestamp: null,
    awayReason: '',
    
    // Flags
    soundEnabled: true,
    isDisqualified: false,
    isExamSubmitted: false,
    cameraActive: false,
    mediaStream: null,
    
    // Active detector toggles
    toggles: {
      tabDetect: true,
      blurDetect: true,
      fullscreenLock: true,
      mouseleaveDetect: true,
      clipboardGuard: true,
      devtoolsDetect: true,
    },
    
    // Audit Log Array
    auditLogs: [],
    
    // Exam Question Data
    currentQuestion: 0,
    questions: [
      {
        topic: 'Web Security & Browser APIs',
        question: 'Which modern Web API allows developers to detect when a browser tab becomes hidden or visible again to the user?',
        options: [
          'Document.visibilityState and visibilitychange event',
          'Window.onTabExit() native hook',
          'Navigator.tabSwitchDetector()',
          'ScreenOrientation.hiddenState'
        ],
        correct: 0,
        selected: null
      },
      {
        topic: 'Window Focus & Proctoring Mechanisms',
        question: 'What is the key technical difference between the "blur" event on Window and the "visibilitychange" event on Document?',
        options: [
          'They are completely identical aliases in modern ECMAScript standard',
          'Blur fires whenever the window loses focus (e.g. clicking external app/split screen), while visibilitychange specifically detects if the tab/page is visually hidden or minimized',
          'Visibilitychange only works on mobile devices, whereas blur is desktop exclusive',
          'Blur event requires full administrative permissions in Manifest V3'
        ],
        correct: 1,
        selected: null
      },
      {
        topic: 'Client-Side Proctoring Security',
        question: 'Why must client-side proctoring detections (like tab switches and window blurs) be paired with server-side validation & audit logging?',
        options: [
          'Because client-side JavaScript execution can be inspected or paused via DevTools or browser extensions by an adversarial user',
          'Because browsers automatically erase all local events after 60 seconds',
          'Because JavaScript is inherently single-threaded and cannot measure time',
          'Server-side validation is actually unnecessary for online examinations'
        ],
        correct: 0,
        selected: null
      }
    ]
  };

  // ==========================================================================
  // DOM Elements
  // ==========================================================================
  const dom = {
    // Header & Timer
    sessionTimer: document.getElementById('session-timer'),
    hudStatusBadge: document.getElementById('hud-status-badge'),
    statusText: document.getElementById('status-text'),
    threatFlash: document.getElementById('threat-flash-overlay'),
    
    // Controls
    btnFullscreen: document.getElementById('btn-fullscreen'),
    btnAudioToggle: document.getElementById('btn-audio-toggle'),
    soundIconOn: document.getElementById('sound-icon-on'),
    soundIconOff: document.getElementById('sound-icon-off'),
    soundBtnText: document.getElementById('sound-btn-text'),
    btnSimulateViolation: document.getElementById('btn-simulate-violation'),
    btnReset: document.getElementById('btn-reset'),
    
    // Metric Cards
    gaugeFill: document.getElementById('gauge-fill'),
    integrityPercent: document.getElementById('integrity-percent'),
    integrityDescription: document.getElementById('integrity-description'),
    strikeCounter: document.getElementById('strike-counter'),
    strikeBar1: document.getElementById('strike-bar-1'),
    strikeBar2: document.getElementById('strike-bar-2'),
    strikeBar3: document.getElementById('strike-bar-3'),
    tabSwitchCount: document.getElementById('tab-switch-count'),
    lastTabTime: document.getElementById('last-tab-time'),
    windowBlurCount: document.getElementById('window-blur-count'),
    blurStatus: document.getElementById('blur-status'),
    timeAwayVal: document.getElementById('time-away-val'),
    
    // Exam Sandbox
    qCounter: document.getElementById('q-counter'),
    questionTopic: document.querySelector('.question-topic'),
    questionText: document.getElementById('question-text'),
    optionsGroup: document.getElementById('options-group'),
    studentNotes: document.getElementById('student-notes'),
    btnPrevQ: document.getElementById('btn-prev-q'),
    btnNextQ: document.getElementById('btn-next-q'),
    btnSubmitExam: document.getElementById('btn-submit-exam'),
    
    // Surveillance & Webcam
    btnToggleCam: document.getElementById('btn-toggle-cam'),
    camBtnLabel: document.getElementById('cam-btn-label'),
    webcamVideo: document.getElementById('webcam-video'),
    cameraSimulationHud: document.getElementById('camera-simulation-hud'),
    feedStatusText: document.getElementById('feed-status-text'),
    aiFaceStatus: document.getElementById('ai-face-status'),
    
    // Toggles
    toggleTabDetect: document.getElementById('toggle-tab-detect'),
    toggleBlurDetect: document.getElementById('toggle-blur-detect'),
    toggleFullscreenLock: document.getElementById('toggle-fullscreen-lock'),
    toggleMouseleaveDetect: document.getElementById('toggle-mouseleave-detect'),
    toggleClipboardGuard: document.getElementById('toggle-clipboard-guard'),
    toggleDevtoolsDetect: document.getElementById('toggle-devtools-detect'),
    
    // Logs & Reports
    liveThreatBadge: document.getElementById('live-threat-badge'),
    auditLogStream: document.getElementById('audit-log-stream'),
    btnExportLog: document.getElementById('btn-export-log'),
    btnPrintReport: document.getElementById('btn-print-report'),
    btnClearLog: document.getElementById('btn-clear-log'),
    logFilterPills: document.getElementById('log-filter-pills'),
    strikeLimitSelect: document.getElementById('strike-limit-select'),
    dynamicFavicon: document.getElementById('dynamic-favicon'),
    metricDenom: document.querySelector('.metric-denom'),
    
    // Modals
    violationModal: document.getElementById('violation-modal'),
    modalViolationTitle: document.getElementById('modal-violation-title'),
    modalViolationMsg: document.getElementById('modal-violation-msg'),
    modalViolationMeta: document.getElementById('modal-violation-meta'),
    btnDismissViolation: document.getElementById('btn-dismiss-violation'),
    
    // Lockout
    lockoutScreen: document.getElementById('lockout-screen'),
    lockoutTrustScore: document.getElementById('lockout-trust-score'),
    lockoutSwitches: document.getElementById('lockout-switches'),
    lockoutTimeAway: document.getElementById('lockout-time-away'),
    btnLockoutExport: document.getElementById('btn-lockout-export'),
    btnLockoutReset: document.getElementById('btn-lockout-reset'),
    
    // Toasts
    toastContainer: document.getElementById('toast-container')
  };

  // ==========================================================================
  // Dynamic Tab Title & Favicon Flasher
  // ==========================================================================
  let titleFlashInterval = null;
  const FAVICON_CYAN = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2300e5ff'><circle cx='12' cy='12' r='10'/></svg>";
  const FAVICON_RED = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23f43f5e'><polygon points='12,2 2,22 22,22'/><circle cx='12' cy='17' r='1.5' fill='%23fff'/></svg>";

  function startTitleFaviconFlash() {
    let toggle = false;
    if (titleFlashInterval) clearInterval(titleFlashInterval);
    titleFlashInterval = setInterval(() => {
      document.title = toggle ? '⚠️ RETURN TO TEST! | SentinelTab' : '🚨 CHEATING DETECTED! | SentinelTab';
      if (dom.dynamicFavicon) {
        dom.dynamicFavicon.href = toggle ? FAVICON_RED : FAVICON_CYAN;
      }
      toggle = !toggle;
    }, 700);
  }

  function stopTitleFaviconFlash() {
    if (titleFlashInterval) {
      clearInterval(titleFlashInterval);
      titleFlashInterval = null;
    }
    document.title = 'SentinelTab - Anti-Cheating & Tab Switch Detection System';
    if (dom.dynamicFavicon) {
      dom.dynamicFavicon.href = FAVICON_CYAN;
    }
  }

  // ==========================================================================
  // Web Audio Synthesizer (Native Browser Audio Oscillator)
  // ==========================================================================
  let audioCtx = null;

  function initAudioContext() {
    if (!audioCtx) {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (AudioContextClass) {
        audioCtx = new AudioContextClass();
      }
    }
    if (audioCtx && audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
  }

  const Sound = {
    // Sharp Warning Beep
    beep() {
      if (!state.soundEnabled) return;
      initAudioContext();
      if (!audioCtx) return;

      try {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(750, audioCtx.currentTime);
        gain.gain.setValueAtTime(0.2, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.35);

        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.35);
      } catch (e) {
        console.warn('Audio play failed', e);
      }
    },

    // High Alert Siren (Two-tone alarm)
    siren() {
      if (!state.soundEnabled) return;
      initAudioContext();
      if (!audioCtx) return;

      try {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'triangle';

        const now = audioCtx.currentTime;
        osc.frequency.setValueAtTime(900, now);
        osc.frequency.linearRampToValueAtTime(500, now + 0.2);
        osc.frequency.linearRampToValueAtTime(900, now + 0.4);
        osc.frequency.linearRampToValueAtTime(500, now + 0.6);

        gain.gain.setValueAtTime(0.35, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.7);

        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start(now);
        osc.stop(now + 0.7);
      } catch (e) {
        console.warn('Audio play failed', e);
      }
    },

    // Success Chime (Exam submit / Clean return)
    success() {
      if (!state.soundEnabled) return;
      initAudioContext();
      if (!audioCtx) return;

      try {
        const freqs = [523.25, 659.25, 783.99]; // C5, E5, G5
        freqs.forEach((freq, idx) => {
          const osc = audioCtx.createOscillator();
          const gain = audioCtx.createGain();
          osc.type = 'sine';
          osc.frequency.setValueAtTime(freq, audioCtx.currentTime + idx * 0.1);
          gain.gain.setValueAtTime(0.18, audioCtx.currentTime + idx * 0.1);
          gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + idx * 0.1 + 0.4);

          osc.connect(gain);
          gain.connect(audioCtx.destination);
          osc.start(audioCtx.currentTime + idx * 0.1);
          osc.stop(audioCtx.currentTime + idx * 0.1 + 0.4);
        });
      } catch (e) {
        console.warn('Audio play failed', e);
      }
    }
  };

  // ==========================================================================
  // Session Timer
  // ==========================================================================
  function startSessionTimer() {
    if (state.timerInterval) clearInterval(state.timerInterval);
    state.timerInterval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - state.startTime) / 1000);
      const hrs = String(Math.floor(elapsed / 3600)).padStart(2, '0');
      const mins = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
      const secs = String(elapsed % 60).padStart(2, '0');
      dom.sessionTimer.textContent = `${hrs}:${mins}:${secs}`;
    }, 1000);
  }

  function getTimestampFormatted() {
    const d = new Date();
    return d.toTimeString().split(' ')[0];
  }

  // ==========================================================================
  // Audit Logging & Incident Feed
  // ==========================================================================
  function logEvent(category, severity, message, extra = {}) {
    const timeStr = getTimestampFormatted();
    const eventObj = {
      id: 'LOG_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      timestamp: timeStr,
      category,
      severity, // 'info', 'warning', 'critical'
      message,
      extra
    };

    state.auditLogs.unshift(eventObj); // Keep in memory

    // Render in UI
    const entryEl = document.createElement('div');
    entryEl.className = `log-entry log-entry-${severity}`;
    
    let badgeClass = 'badge-info';
    if (severity === 'warning') badgeClass = 'badge-warn';
    if (severity === 'critical') badgeClass = 'badge-crimson';

    entryEl.innerHTML = `
      <span class="log-timestamp">${timeStr}</span>
      <span class="log-badge ${badgeClass}">${severity.toUpperCase()}</span>
      <div class="log-message">
        <strong>[${category}]</strong> ${escapeHtml(message)}
      </div>
    `;

    dom.auditLogStream.insertBefore(entryEl, dom.auditLogStream.firstChild);

    // Update incident counter badge
    const incidentCount = state.auditLogs.filter(l => l.severity !== 'info').length;
    dom.liveThreatBadge.textContent = `${incidentCount} INCIDENT${incidentCount === 1 ? '' : 'S'}`;
  }

  function escapeHtml(str) {
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag));
  }

  // ==========================================================================
  // Toast Notifications
  // ==========================================================================
  function showToast(message, type = 'warning', durationMs = 3500) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = '⚠️';
    if (type === 'danger') icon = '🚨';
    if (type === 'success') icon = '✅';

    toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(message)}</span>`;
    dom.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, durationMs);
  }

  // ==========================================================================
  // Integrity Score & Strike Management
  // ==========================================================================
  function addStrike(reason, penalty = 20) {
    if (state.isDisqualified) return;

    state.strikes = Math.min(state.strikes + 1, state.maxStrikes);
    state.integrityScore = Math.max(0, state.integrityScore - penalty);
    updateMetricsUI();

    Sound.siren();

    // Visual strike animation
    dom.strikeCounter.textContent = state.strikes;
    if (state.strikes >= 1) dom.strikeBar1.classList.add('active');
    if (state.strikes >= 2) dom.strikeBar2.classList.add('active');
    if (state.strikes >= 3) dom.strikeBar3.classList.add('active');

    // Trigger Lockout if reached 3 strikes
    if (state.strikes >= state.maxStrikes) {
      triggerDisqualification(reason);
    }
  }

  function deductIntegrityOnly(penalty, reason) {
    if (state.isDisqualified) return;
    state.integrityScore = Math.max(0, state.integrityScore - penalty);
    updateMetricsUI();
    Sound.beep();
  }

  function updateMetricsUI() {
    // Gauge calculation: circumference of r=48 is 2 * PI * 48 = 301.59
    const circumference = 301.59;
    const offset = circumference * (1 - state.integrityScore / 100);
    dom.gaugeFill.style.strokeDashoffset = offset;
    dom.integrityPercent.textContent = `${Math.round(state.integrityScore)}%`;

    // Dynamic Gauge Colors
    if (state.integrityScore >= 80) {
      dom.gaugeFill.style.stroke = 'var(--emerald-success)';
      dom.integrityDescription.textContent = 'High Integrity: Assessment clean';
      setHUDStatus('MONITORING ACTIVE', 'normal');
    } else if (state.integrityScore >= 50) {
      dom.gaugeFill.style.stroke = 'var(--amber-warning)';
      dom.integrityDescription.textContent = 'Caution: Multiple breaches flagged';
      setHUDStatus('SECURITY WARNING', 'warning');
    } else {
      dom.gaugeFill.style.stroke = 'var(--crimson-danger)';
      dom.integrityDescription.textContent = 'High Risk: Critical infractions';
      setHUDStatus('CRITICAL THREAT', 'danger');
    }

    dom.tabSwitchCount.textContent = state.tabSwitches;
    dom.windowBlurCount.textContent = state.windowBlurs;
    dom.timeAwayVal.innerHTML = `${(state.totalTimeAwayMs / 1000).toFixed(1)}<small>s</small>`;
  }

  function setHUDStatus(text, level) {
    dom.statusText.textContent = text;
    dom.hudStatusBadge.className = 'hud-status-badge';
    if (level === 'warning') dom.hudStatusBadge.classList.add('status-warning');
    if (level === 'danger') dom.hudStatusBadge.classList.add('status-danger');
  }

  // ==========================================================================
  // Violation Modal & Lockout Overlay
  // ==========================================================================
  function showViolationModal(title, message, durationStr) {
    if (state.isDisqualified) return;

    dom.modalViolationTitle.textContent = title;
    dom.modalViolationMsg.textContent = message;
    dom.modalViolationMeta.innerHTML = `
      <span>Away Duration: <strong>${durationStr}</strong></span>
      <span>•</span>
      <span id="modal-strike-text">Strike ${state.strikes} of ${state.maxStrikes}</span>
    `;

    dom.violationModal.classList.remove('hidden');
  }

  function triggerDisqualification(reason) {
    state.isDisqualified = true;
    dom.lockoutTrustScore.textContent = `${Math.round(state.integrityScore)}%`;
    dom.lockoutSwitches.textContent = state.tabSwitches;
    dom.lockoutTimeAway.textContent = `${(state.totalTimeAwayMs / 1000).toFixed(1)}s`;
    
    dom.violationModal.classList.add('hidden');
    dom.lockoutScreen.classList.remove('hidden');

    logEvent('TERMINATION', 'critical', `Assessment disqualified. Cause: ${reason}`);
  }

  // ==========================================================================
  // CORE DETECTION VECTOR 1: Tab Switch & Page Visibility API
  // ==========================================================================
  function setupVisibilityDetection() {
    document.addEventListener('visibilitychange', () => {
      if (!state.toggles.tabDetect || state.isDisqualified) return;

      if (document.hidden) {
        // Tab is now hidden (user switched tabs or minimized window)
        state.isAway = true;
        state.awayStartTimestamp = performance.now();
        state.awayReason = 'TAB_SWITCH';
        
        dom.threatFlash.classList.add('active');
        document.body.classList.add('violation-active');
        startTitleFaviconFlash();
        
        logEvent('TAB_SWITCH', 'critical', 'Candidate navigated away from current tab (Tab hidden).');
        Sound.beep();
      } else {
        // Tab is visible again (user returned)
        dom.threatFlash.classList.remove('active');
        document.body.classList.remove('violation-active');
        stopTitleFaviconFlash();

        if (state.isAway && state.awayStartTimestamp) {
          const awayDurationMs = performance.now() - state.awayStartTimestamp;
          state.totalTimeAwayMs += awayDurationMs;
          const awaySec = (awayDurationMs / 1000).toFixed(1);
          state.tabSwitches += 1;
          
          dom.lastTabTime.textContent = `Last: ${awaySec}s away`;
          
          logEvent('TAB_RESTORED', 'warning', `Returned to tab after being away for ${awaySec} seconds.`);
          
          // Apply strike & penalty
          addStrike(`Tab switch of ${awaySec}s`, 25);

          showViolationModal(
            'TAB SWITCH DETECTED!',
            `You switched away to another browser tab or minimized this window. All tab movements are recorded in the security audit report.`,
            `${awaySec}s`
          );

          state.isAway = false;
          state.awayStartTimestamp = null;
        }
      }
    });
  }

  // ==========================================================================
  // CORE DETECTION VECTOR 2: Window Focus & Blur (App Switch / Split Screen)
  // ==========================================================================
  function setupFocusBlurDetection() {
    window.addEventListener('blur', () => {
      if (!state.toggles.blurDetect || state.isDisqualified) return;

      // If already handled by visibility change (tab hidden), avoid duplicate strike
      if (document.hidden) return;

      state.windowBlurs += 1;
      dom.blurStatus.textContent = 'Focus: Lost Focus';
      dom.threatFlash.classList.add('active');

      logEvent('WINDOW_BLUR', 'warning', 'Browser window lost focus. Candidate clicked another app, second screen, or external tool.');
      
      deductIntegrityOnly(8, 'Window blur');
      showToast('⚠️ Window Focus Lost! Please keep attention focused inside assessment.', 'warning');
    });

    window.addEventListener('focus', () => {
      if (!state.toggles.blurDetect) return;
      
      dom.blurStatus.textContent = 'Focus: In Window';
      if (!document.hidden) {
        dom.threatFlash.classList.remove('active');
      }
      logEvent('WINDOW_FOCUS', 'info', 'Browser window regained focus.');
    });
  }

  // ==========================================================================
  // CORE DETECTION VECTOR 3: Fullscreen Compliance
  // ==========================================================================
  function setupFullscreenDetection() {
    const handleFullscreenChange = () => {
      const isFs = !!(document.fullscreenElement || document.webkitFullscreenElement);
      
      if (isFs) {
        dom.btnFullscreen.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3"/>
          </svg>
          <span class="btn-text">Exit Fullscreen</span>
        `;
        logEvent('FULLSCREEN', 'info', 'Entered Fullscreen proctored environment.');
      } else {
        dom.btnFullscreen.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/>
          </svg>
          <span class="btn-text">Fullscreen</span>
        `;

        if (state.toggles.fullscreenLock && !state.isDisqualified && !state.isExamSubmitted) {
          logEvent('FULLSCREEN_EXIT', 'critical', 'Candidate exited Fullscreen mode via ESC or window restore.');
          addStrike('Fullscreen mode exited', 15);
          showToast('🚨 Fullscreen mode exited! Re-enter fullscreen immediately.', 'danger', 4500);
        }
      }
    };

    document.addEventListener('fullscreenchange', handleFullscreenChange);
    document.addEventListener('webkitfullscreenchange', handleFullscreenChange);

    dom.btnFullscreen.addEventListener('click', () => {
      initAudioContext();
      if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().catch(err => {
          showToast(`Could not enter fullscreen: ${err.message}`, 'warning');
        });
      } else {
        document.exitFullscreen();
      }
    });
  }

  // ==========================================================================
  // CORE DETECTION VECTOR 4: Mouse Viewport Boundary (Leaving towards tabs)
  // ==========================================================================
  function setupMouseLeaveDetection() {
    document.documentElement.addEventListener('mouseleave', (e) => {
      if (!state.toggles.mouseleaveDetect || state.isDisqualified) return;

      // Detect if cursor exited through the top boundary (towards browser tabs / URL bar)
      if (e.clientY <= 0) {
        logEvent('MOUSE_LEAVE', 'warning', 'Cursor departed test boundary towards browser tab strip / address bar.');
        showToast('⚠️ Cursor left assessment area (tab navigation suspected)', 'warning', 2500);
        Sound.beep();
      }
    });
  }

  // ==========================================================================
  // CORE DETECTION VECTOR 5: Keyboard Shortcuts & Clipboard Guard
  // ==========================================================================
  function setupShortcutAndClipboardShield() {
    window.addEventListener('keydown', (e) => {
      if (!state.toggles.clipboardGuard || state.isDisqualified) return;

      const isCtrlOrCmd = e.ctrlKey || e.metaKey;
      const key = e.key.toUpperCase();

      // Block F12 (Inspect)
      if (e.key === 'F12') {
        e.preventDefault();
        blockAndLogAction('DevTools Key (F12) intercepted');
        return;
      }

      // Block Ctrl+Shift+I / Ctrl+Shift+J / Ctrl+Shift+C (DevTools)
      if (isCtrlOrCmd && e.shiftKey && (key === 'I' || key === 'J' || key === 'C')) {
        e.preventDefault();
        blockAndLogAction(`Inspect shortcut (${isCtrlOrCmd ? 'Ctrl/Cmd+' : ''}Shift+${key}) blocked`);
        return;
      }

      // Block Ctrl+C (Copy)
      if (isCtrlOrCmd && key === 'C') {
        e.preventDefault();
        blockAndLogAction('Copy shortcut (Ctrl+C) blocked');
        return;
      }

      // Block Ctrl+V (Paste)
      if (isCtrlOrCmd && key === 'V') {
        e.preventDefault();
        blockAndLogAction('Paste shortcut (Ctrl+V) blocked');
        return;
      }

      // Block Ctrl+X (Cut)
      if (isCtrlOrCmd && key === 'X') {
        e.preventDefault();
        blockAndLogAction('Cut shortcut (Ctrl+X) blocked');
        return;
      }

      // Block Ctrl+U (View Source)
      if (isCtrlOrCmd && key === 'U') {
        e.preventDefault();
        blockAndLogAction('View Source shortcut (Ctrl+U) blocked');
        return;
      }

      // Block PrintScreen
      if (e.key === 'PrintScreen') {
        e.preventDefault();
        blockAndLogAction('PrintScreen attempt intercepted');
        return;
      }

      // Detect Alt key press (precursor to Alt+Tab)
      if (e.key === 'Alt') {
        logEvent('KEY_SUSPECT', 'warning', 'Alt modifier pressed (Potential Alt+Tab window switch attempt)');
      }
    });

    // Native clipboard event listeners
    ['copy', 'paste', 'cut'].forEach(evtType => {
      document.addEventListener(evtType, (e) => {
        if (!state.toggles.clipboardGuard) return;
        e.preventDefault();
        blockAndLogAction(`Clipboard operation [${evtType.toUpperCase()}] blocked`);
      });
    });

    // Disable Right-Click Context Menu
    document.addEventListener('contextmenu', (e) => {
      if (!state.toggles.clipboardGuard) return;
      e.preventDefault();
      blockAndLogAction('Right-click context menu restricted');
    });

    function blockAndLogAction(actionDesc) {
      state.shortcutAttempts += 1;
      deductIntegrityOnly(4, actionDesc);
      showToast(`⛔ Restricted: ${actionDesc}`, 'danger', 3000);
      logEvent('INPUT_SHIELD', 'warning', actionDesc);
    }
  }

  // ==========================================================================
  // CORE DETECTION VECTOR 6: DevTools Trap (Dimensions & Console)
  // ==========================================================================
  function setupDevToolsDetection() {
    let devToolsOpen = false;

    // Outer vs Inner window threshold heuristic
    const checkDevToolsSize = () => {
      if (!state.toggles.devtoolsDetect || state.isDisqualified) return;

      const widthDiff = window.outerWidth - window.innerWidth;
      const heightDiff = window.outerHeight - window.innerHeight;
      const threshold = 160;

      const isOpen = widthDiff > threshold || heightDiff > threshold;
      if (isOpen && !devToolsOpen) {
        devToolsOpen = true;
        logEvent('DEVTOOLS', 'critical', 'Browser Developer Tools / Console window opened.');
        addStrike('Developer Tools opened', 25);
        showToast('🚨 Developer Tools detected! Inspect mode is prohibited.', 'danger', 4000);
      } else if (!isOpen && devToolsOpen) {
        devToolsOpen = false;
        logEvent('DEVTOOLS', 'info', 'Developer tools closed.');
      }
    };

    window.addEventListener('resize', checkDevToolsSize);
    setInterval(checkDevToolsSize, 1500);
  }

  // ==========================================================================
  // Webcam Feed Handler & AI Proctor HUD Simulation
  // ==========================================================================
  function setupWebcamHandler() {
    dom.btnToggleCam.addEventListener('click', async () => {
      initAudioContext();

      if (!state.cameraActive) {
        // Try enabling real camera
        try {
          if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
            state.mediaStream = await navigator.mediaDevices.getUserMedia({
              video: { width: { ideal: 640 }, height: { ideal: 480 } }
            });
            dom.webcamVideo.srcObject = state.mediaStream;
            dom.webcamVideo.classList.remove('hidden');
            dom.feedStatusText.textContent = 'OPTICAL FEED: LIVE';
            dom.camBtnLabel.textContent = 'Disable Camera';
            state.cameraActive = true;
            logEvent('CAMERA', 'info', 'Physical webcam feed linked to candidate HUD.');
            showToast('📹 Webcam connected for proctoring', 'success');
          } else {
            throw new Error('Webcam API not supported in this browser context');
          }
        } catch (err) {
          console.warn('Webcam permission denied or error:', err);
          showToast('⚠️ Camera access denied or unavailable. Simulation active.', 'warning');
          dom.feedStatusText.textContent = 'SIMULATION RUNNING';
        }
      } else {
        // Disable camera
        if (state.mediaStream) {
          state.mediaStream.getTracks().forEach(track => track.stop());
          state.mediaStream = null;
        }
        dom.webcamVideo.classList.add('hidden');
        dom.feedStatusText.textContent = 'SIMULATION MODE';
        dom.camBtnLabel.textContent = 'Enable Camera';
        state.cameraActive = false;
        logEvent('CAMERA', 'info', 'Camera feed disabled.');
      }
    });

    // Simulated FPS jitter for realistic proctor HUD
    setInterval(() => {
      const fpsEl = document.getElementById('fps-counter');
      if (fpsEl) {
        const fps = Math.floor(29 + Math.random() * 3);
        fpsEl.textContent = `${fps} FPS`;
      }
    }, 1200);
  }

  // ==========================================================================
  // Interactive Assessment Sandbox Logic
  // ==========================================================================
  function renderQuestion(index) {
    const q = state.questions[index];
    if (!q) return;

    dom.qCounter.textContent = `Question ${index + 1} of ${state.questions.length}`;
    dom.questionTopic.textContent = `Topic: ${q.topic}`;
    dom.questionText.textContent = q.question;

    // Render options
    dom.optionsGroup.innerHTML = '';
    q.options.forEach((optText, optIdx) => {
      const isChecked = q.selected === optIdx ? 'checked' : '';
      const label = document.createElement('label');
      label.className = 'option-card';
      label.setAttribute('for', `opt-${optIdx}`);
      label.innerHTML = `
        <input type="radio" name="exam-opt" id="opt-${optIdx}" value="${optIdx}" ${isChecked}>
        <span class="custom-radio"></span>
        <span class="option-text">${escapeHtml(optText)}</span>
      `;
      
      label.querySelector('input').addEventListener('change', () => {
        initAudioContext();
        q.selected = optIdx;
      });

      dom.optionsGroup.appendChild(label);
    });

    // Buttons state
    dom.btnPrevQ.disabled = index === 0;
    if (index === state.questions.length - 1) {
      dom.btnNextQ.classList.add('hidden');
      dom.btnSubmitExam.classList.remove('hidden');
    } else {
      dom.btnNextQ.classList.remove('hidden');
      dom.btnSubmitExam.classList.add('hidden');
    }
  }

  function setupAssessmentNavigation() {
    renderQuestion(state.currentQuestion);

    dom.btnPrevQ.addEventListener('click', () => {
      initAudioContext();
      if (state.currentQuestion > 0) {
        state.currentQuestion--;
        renderQuestion(state.currentQuestion);
      }
    });

    dom.btnNextQ.addEventListener('click', () => {
      initAudioContext();
      if (state.currentQuestion < state.questions.length - 1) {
        state.currentQuestion++;
        renderQuestion(state.currentQuestion);
      }
    });

    dom.btnSubmitExam.addEventListener('click', () => {
      initAudioContext();
      state.isExamSubmitted = true;
      Sound.success();

      // Calculate score
      let correctCount = 0;
      state.questions.forEach(q => {
        if (q.selected === q.correct) correctCount++;
      });

      logEvent('EXAM_SUBMISSION', 'info', `Candidate completed and submitted assessment. Academic Score: ${correctCount}/${state.questions.length}. Integrity: ${Math.round(state.integrityScore)}%`);

      alert(`🎉 Assessment Successfully Submitted!\n\nScore: ${correctCount} / ${state.questions.length} Correct\nProctoring Integrity: ${Math.round(state.integrityScore)}%\nTotal Tab Switches: ${state.tabSwitches}\nTotal Time Away: ${(state.totalTimeAwayMs / 1000).toFixed(1)}s\n\nFull security audit is ready for export!`);
    });
  }

  // ==========================================================================
  // Shield Configuration Toggles
  // ==========================================================================
  function setupToggles() {
    const toggleMap = [
      { el: dom.toggleTabDetect, key: 'tabDetect', name: 'Tab Switch Monitor' },
      { el: dom.toggleBlurDetect, key: 'blurDetect', name: 'Window Blur Monitor' },
      { el: dom.toggleFullscreenLock, key: 'fullscreenLock', name: 'Fullscreen Lock' },
      { el: dom.toggleMouseleaveDetect, key: 'mouseleaveDetect', name: 'Mouse Boundary Guard' },
      { el: dom.toggleClipboardGuard, key: 'clipboardGuard', name: 'Clipboard & Shortcut Shield' },
      { el: dom.toggleDevtoolsDetect, key: 'devtoolsDetect', name: 'DevTools Trap' },
    ];

    toggleMap.forEach(({ el, key, name }) => {
      el.addEventListener('change', (e) => {
        state.toggles[key] = e.target.checked;
        logEvent('SHIELD_CONFIG', 'info', `${name} set to ${e.target.checked ? 'ENABLED' : 'DISABLED'}`);
      });
    });
  }

  // ==========================================================================
  // Controls & Actions
  // ==========================================================================
  function setupControls() {
    // Sound Toggle
    dom.btnAudioToggle.addEventListener('click', () => {
      initAudioContext();
      state.soundEnabled = !state.soundEnabled;
      if (state.soundEnabled) {
        dom.soundIconOn.classList.remove('hidden');
        dom.soundIconOff.classList.add('hidden');
        dom.soundBtnText.textContent = 'Alarm ON';
        Sound.beep();
      } else {
        dom.soundIconOn.classList.add('hidden');
        dom.soundIconOff.classList.remove('hidden');
        dom.soundBtnText.textContent = 'Alarm OFF';
      }
      logEvent('AUDIO', 'info', `Acoustic siren alerts ${state.soundEnabled ? 'activated' : 'muted'}.`);
    });

    // Simulate Violation Test
    dom.btnSimulateViolation.addEventListener('click', () => {
      initAudioContext();
      state.tabSwitches += 1;
      state.totalTimeAwayMs += 3200;
      addStrike('Simulated Tab Switch / Violation trigger', 20);
      showViolationModal(
        'TEST VIOLATION TRIGGERED!',
        'This is a demonstration of how SentinelTab alerts proctors and candidate when an unauthorized tab switch occurs.',
        '3.2s'
      );
      logEvent('TEST_SIMULATION', 'warning', 'Manual test alert triggered via Test Button.');
    });

    // Reset Session
    dom.btnReset.addEventListener('click', () => {
      if (confirm('Reset session metrics, strike counts, and activity logs?')) {
        resetSession();
      }
    });

    // Dismiss violation modal
    dom.btnDismissViolation.addEventListener('click', () => {
      dom.violationModal.classList.add('hidden');
    });

    // Lockout Reset & Export
    dom.btnLockoutReset.addEventListener('click', () => {
      resetSession();
      dom.lockoutScreen.classList.add('hidden');
    });

    dom.btnLockoutExport.addEventListener('click', exportAuditJSON);
    dom.btnExportLog.addEventListener('click', exportAuditJSON);

    // Print Official Report / PDF
    if (dom.btnPrintReport) {
      dom.btnPrintReport.addEventListener('click', () => {
        initAudioContext();
        window.print();
        logEvent('REPORT', 'info', 'Official proctoring certificate printed / saved to PDF.');
      });
    }

    // Strike Sensitivity Selector
    if (dom.strikeLimitSelect) {
      dom.strikeLimitSelect.addEventListener('change', (e) => {
        state.maxStrikes = parseInt(e.target.value, 10) || 3;
        if (dom.metricDenom) {
          dom.metricDenom.textContent = `/ ${state.maxStrikes} MAX`;
        }
        logEvent('CONFIG', 'info', `Max allowed violation strikes changed to ${state.maxStrikes}.`);
        showToast(`⚙️ Strike limit set to ${state.maxStrikes}`, 'info');
      });
    }

    // Audit Log Filter Pills
    if (dom.logFilterPills) {
      const filterButtons = dom.logFilterPills.querySelectorAll('.filter-pill');
      filterButtons.forEach(btn => {
        btn.addEventListener('click', () => {
          filterButtons.forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          const filter = btn.dataset.filter;
          filterAuditLogs(filter);
        });
      });
    }

    // Clear logs
    dom.btnClearLog.addEventListener('click', () => {
      dom.auditLogStream.innerHTML = '';
      state.auditLogs = [];
      logEvent('LOGS', 'info', 'Audit event history cleared by administrator.');
    });
  }

  function filterAuditLogs(filter) {
    const entries = dom.auditLogStream.querySelectorAll('.log-entry');
    entries.forEach(entry => {
      if (filter === 'all') {
        entry.style.display = 'flex';
      } else if (filter === 'critical') {
        entry.style.display = entry.classList.contains('log-entry-critical') ? 'flex' : 'none';
      } else if (filter === 'warning') {
        entry.style.display = entry.classList.contains('log-entry-warning') ? 'flex' : 'none';
      }
    });
  }

  function resetSession() {
    state.startTime = Date.now();
    state.integrityScore = 100;
    state.strikes = 0;
    state.tabSwitches = 0;
    state.windowBlurs = 0;
    state.shortcutAttempts = 0;
    state.totalTimeAwayMs = 0;
    state.isAway = false;
    state.isDisqualified = false;
    state.isExamSubmitted = false;
    
    dom.strikeCounter.textContent = '0';
    dom.strikeBar1.classList.remove('active');
    dom.strikeBar2.classList.remove('active');
    dom.strikeBar3.classList.remove('active');
    dom.threatFlash.classList.remove('active');
    dom.lastTabTime.textContent = 'Last: None';
    dom.blurStatus.textContent = 'Focus: In Window';

    updateMetricsUI();
    logEvent('RESET', 'info', 'Proctor session restored to initial 100% integrity.');
    showToast('✨ Session reset successfully', 'success');
  }

  function exportAuditJSON() {
    const reportData = {
      system: 'SentinelTab Proctoring Suite',
      generatedAt: new Date().toISOString(),
      sessionSummary: {
        durationSeconds: Math.floor((Date.now() - state.startTime) / 1000),
        finalIntegrityScore: `${Math.round(state.integrityScore)}%`,
        strikesAccumulated: `${state.strikes} / ${state.maxStrikes}`,
        totalTabSwitches: state.tabSwitches,
        totalWindowBlurs: state.windowBlurs,
        totalTimeAwaySeconds: (state.totalTimeAwayMs / 1000).toFixed(1),
        disqualified: state.isDisqualified,
        examSubmitted: state.isExamSubmitted
      },
      events: state.auditLogs
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel_audit_report_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast('📥 Incident audit log exported as JSON', 'success');
  }

  // ==========================================================================
  // Initialization
  // ==========================================================================
  function init() {
    startSessionTimer();
    updateMetricsUI();
    setupVisibilityDetection();
    setupFocusBlurDetection();
    setupFullscreenDetection();
    setupMouseLeaveDetection();
    setupShortcutAndClipboardShield();
    setupDevToolsDetection();
    setupWebcamHandler();
    setupAssessmentNavigation();
    setupToggles();
    setupControls();

    // User first interaction listener to initialize AudioContext
    window.addEventListener('click', initAudioContext, { once: true });
    window.addEventListener('keydown', initAudioContext, { once: true });
  }

  // Boot on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

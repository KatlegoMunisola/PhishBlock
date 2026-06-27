/**
 * PhishBlock - Content Script
 * Scans the DOM, visible text, and forms to detect phishing indicators.
 * Injects a full-screen warning overlay if threat score is high.
 */

// Local whitelist for fast lookup and form audits
const WHITELIST = [
  "microsoftonline.com",
  "office.com",
  "microsoft.com",
  "biust.ac.bw"
];

// High-urgency phrases from the cybersecurity memo
const URGENCY_PHRASES = [
  { phrase: "account expiring", regex: /account\s+expiring/i },
  { phrase: "verify immediately", regex: /verify\s+immediately/i },
  { phrase: "keep credentials", regex: /keep\s+credentials/i },
  { phrase: "action required", regex: /action\s+required/i },
  { phrase: "confirm password", regex: /confirm\s+password/i }
];

// Brand-related login cues
const BRAND_CUES = [
  "sign in to your account",
  "keep me signed in",
  "sign in to biust",
  "biust single sign-on",
  "office 365",
  "office-365"
];

let isBlocked = false;
let observer = null;

// Run scan as soon as DOM is loaded
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initialize);
} else {
  initialize();
}

/**
 * Main initialization function.
 */
function initialize() {
  // Check if developer bypass is already active for this session
  if (sessionStorage.getItem("phishblock_bypass") === "true") {
    console.warn("[PhishBlock] Developer Bypass active. Skipping threat blocking.");
    reportStatus(0, "safe", ["Developer Bypass Active"]);
    return;
  }

  // Ask background worker to check the domain
  chrome.runtime.sendMessage(
    { action: "checkDomain", url: window.location.href },
    (domainResult) => {
      if (chrome.runtime.lastError) {
        console.error("[PhishBlock] Error communicating with service worker:", chrome.runtime.lastError);
        return;
      }

      if (!domainResult) return;

      // If domain is whitelisted, bypass further threat analysis
      if (domainResult.isWhitelisted) {
        reportStatus(0, "safe", []);
        return;
      }

      // Execute initial security scan
      runSecurityScan(domainResult);

      // Set up MutationObserver to catch dynamic DOM loads (e.g. SPAs, dynamic forms)
      setupDynamicObserver(domainResult);
    }
  );
}

/**
 * Reports the threat assessment to the background script.
 */
function reportStatus(score, riskLevel, indicators) {
  chrome.runtime.sendMessage({
    action: "updateTabThreatStatus",
    url: window.location.href,
    title: document.title || "Untitled Page",
    score: score,
    riskLevel: riskLevel,
    indicators: indicators,
    isWhitelisted: false
  });
}

/**
 * Monitors the DOM for changes and runs analysis if new nodes are injected.
 */
function setupDynamicObserver(domainResult) {
  if (observer) return;

  let debounceTimeout;
  observer = new MutationObserver(() => {
    if (isBlocked) return;
    clearTimeout(debounceTimeout);
    debounceTimeout = setTimeout(() => {
      runSecurityScan(domainResult);
    }, 500); // 500ms debounce
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
}

/**
 * Performs heuristic, lexical, and behavioral checks on the DOM.
 */
function runSecurityScan(domainResult) {
  if (isBlocked) return;

  let score = 0;
  const triggeredIndicators = [];

  // --- 1. Domain Status (Analyzed by background.js) ---
  if (domainResult.isLookalike) {
    score += 80;
    triggeredIndicators.push(`Lookalike/Typosquatted domain mimicking ${domainResult.matchedBrand.toUpperCase()}`);
  } else if (domainResult.isSuspiciousKeyword) {
    score += 50;
    triggeredIndicators.push("Domain contains sensitive brand keyword (e.g. microsoft, biust, office365)");
  }

  // --- 2. Lexical Urgency Check ---
  let visibleText = "";
  try {
    visibleText = document.body ? document.body.innerText : "";
  } catch (e) {
    // Body text not accessible (e.g., security restrictions)
  }

  const lexicalTriggers = [];
  URGENCY_PHRASES.forEach(({ phrase, regex }) => {
    if (regex.test(visibleText)) {
      score += 15;
      lexicalTriggers.push(`"${phrase}"`);
    }
  });

  if (lexicalTriggers.length > 0) {
    triggeredIndicators.push(`High-urgency language detected: ${lexicalTriggers.join(", ")}`);
  }

  // --- 3. Visual/Brand Layout Cues ---
  let brandCueDetected = false;
  const brandTriggers = [];

  // Check inputs (placeholders)
  document.querySelectorAll("input").forEach(input => {
    const placeholder = (input.getAttribute("placeholder") || "").toLowerCase();
    BRAND_CUES.forEach(cue => {
      if (placeholder.includes(cue) && !brandTriggers.includes(cue)) {
        brandCueDetected = true;
        brandTriggers.push(cue);
      }
    });
  });

  // Check leaf elements (headings, labels, small divs)
  document.querySelectorAll("label, button, a, h1, h2, h3, div, span").forEach(el => {
    if (el.children.length === 0 && el.textContent) {
      const text = el.textContent.toLowerCase();
      BRAND_CUES.forEach(cue => {
        if (text.includes(cue) && !brandTriggers.includes(cue)) {
          brandCueDetected = true;
          brandTriggers.push(cue);
        }
      });
    }
  });

  // Check images/logos
  document.querySelectorAll("img").forEach(img => {
    const alt = (img.getAttribute("alt") || "").toLowerCase();
    const src = (img.getAttribute("src") || "").toLowerCase();
    const checkBrands = ["microsoft", "office365", "biust", "outlook"];
    checkBrands.forEach(brand => {
      if ((alt.includes(brand) || src.includes(brand)) && !brandTriggers.includes(brand)) {
        brandCueDetected = true;
        brandTriggers.push(`${brand} logo/asset`);
      }
    });
  });

  if (brandCueDetected) {
    score += 25;
    triggeredIndicators.push(`Brand matching login structure/cues: [${brandTriggers.join(", ")}]`);
  }

  // --- 4. Form Destination Auditing ---
  let insecureFormDetected = false;
  document.querySelectorAll("form").forEach(form => {
    const hasPassword = form.querySelector("input[type='password']") !== null;
    if (hasPassword) {
      const action = form.getAttribute("action");
      if (!action) {
        // Submits to the current (non-whitelisted) page
        insecureFormDetected = true;
      } else {
        try {
          // Resolve relative URL to check final target domain
          const resolvedUrl = new URL(action, window.location.href);
          const currentHostname = window.location.hostname;
          const resolvedHostname = resolvedUrl.hostname;

          const isExternal = resolvedHostname !== currentHostname;
          const isNotWhitelisted = !WHITELIST.some(domain => {
            return resolvedHostname === domain || resolvedHostname.endsWith("." + domain);
          });
          const isInsecure = resolvedUrl.protocol === "http:";

          if (isInsecure || (isExternal && isNotWhitelisted)) {
            insecureFormDetected = true;
          }
        } catch (e) {
          // Invalid action target represents an unverified form flow
          insecureFormDetected = true;
        }
      }
    }
  });

  if (insecureFormDetected) {
    score += 70;
    triggeredIndicators.push("Insecure or unverified credential submission form (password input destination)");
  }

  // --- 5. Determine Threat Level & Action ---
  let riskLevel = "safe";
  if (score >= 60) {
    riskLevel = "malicious";
    triggerWarningOverlay(triggeredIndicators, score);
  } else if (score > 15) {
    riskLevel = "suspicious";
  }

  reportStatus(score, riskLevel, triggeredIndicators);
}

/**
 * Injects a Shadow DOM-isolated, full-screen block overlay over the page.
 */
function triggerWarningOverlay(indicators, score) {
  isBlocked = true;
  if (observer) {
    observer.disconnect(); // Stop observing DOM shifts to prevent loops
  }

  // Prevent scroll on host body
  document.body.style.overflow = "hidden";

  // Create overlay container
  const host = document.createElement("div");
  host.id = "phishblock-overlay-host";
  host.style.position = "fixed";
  host.style.top = "0";
  host.style.left = "0";
  host.style.width = "100vw";
  host.style.height = "100vh";
  host.style.zIndex = "2147483647"; // Max z-index
  document.body.appendChild(host);

  // Attach closed Shadow DOM to completely isolate styles
  const shadow = host.attachShadow({ mode: "closed" });

  // Stylesheet for the overlay inside the Shadow DOM
  const style = document.createElement("style");
  style.textContent = `
    :host {
      all: initial;
    }
    .overlay-container {
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: radial-gradient(circle at center, rgba(30, 20, 20, 0.98) 0%, rgba(10, 5, 5, 0.99) 100%);
      font-family: 'Outfit', 'Segoe UI', system-ui, sans-serif;
      color: #F3F4F6;
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 2147483647;
      overflow-y: auto;
    }
    .card {
      max-width: 650px;
      width: 90%;
      background: rgba(255, 255, 255, 0.03);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid rgba(239, 68, 68, 0.2);
      border-radius: 16px;
      padding: 40px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6), 0 0 40px rgba(239, 68, 68, 0.08);
      text-align: center;
      animation: fadeIn 0.4s ease-out;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: scale(0.96); }
      to { opacity: 1; transform: scale(1); }
    }
    .shield-icon {
      width: 80px;
      height: 80px;
      background: rgba(239, 68, 68, 0.1);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px;
      border: 2px solid #EF4444;
      box-shadow: 0 0 20px rgba(239, 68, 68, 0.3);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
      70% { box-shadow: 0 0 0 20px rgba(239, 68, 68, 0); }
      100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }
    .shield-icon svg {
      width: 44px;
      height: 44px;
      fill: #EF4444;
    }
    h1 {
      font-size: 28px;
      font-weight: 700;
      margin: 0 0 12px;
      color: #EF4444;
      letter-spacing: -0.5px;
    }
    .subtitle {
      font-size: 16px;
      color: #9CA3AF;
      margin-bottom: 24px;
    }
    .indicators-box {
      background: rgba(0, 0, 0, 0.25);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 24px;
      text-align: left;
    }
    .indicators-box-title {
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #EF4444;
      font-weight: 600;
      margin-bottom: 8px;
    }
    .indicators-list {
      margin: 0;
      padding-left: 20px;
      font-size: 14px;
      color: #D1D5DB;
      line-height: 1.6;
    }
    .indicators-list li {
      margin-bottom: 6px;
    }
    .memo-callout {
      background: rgba(245, 158, 11, 0.08);
      border-left: 4px solid #F59E0B;
      padding: 16px;
      border-radius: 0 8px 8px 0;
      margin-bottom: 32px;
      text-align: left;
      font-size: 14px;
      line-height: 1.5;
      color: #FBBF24;
    }
    .btn-group {
      display: flex;
      gap: 16px;
      justify-content: center;
    }
    .btn {
      padding: 12px 28px;
      font-size: 15px;
      font-weight: 600;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s ease;
      text-decoration: none;
    }
    .btn-primary {
      background: #EF4444;
      color: white;
      border: none;
      box-shadow: 0 4px 14px rgba(239, 68, 68, 0.3);
    }
    .btn-primary:hover {
      background: #DC2626;
      transform: translateY(-1px);
      box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
    }
    .btn-secondary {
      background: transparent;
      color: #9CA3AF;
      border: 1px solid rgba(255, 255, 255, 0.15);
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.05);
      color: white;
      border-color: rgba(255, 255, 255, 0.3);
    }
    .bypass-link {
      display: block;
      margin-top: 24px;
      font-size: 12px;
      color: #6B7280;
      text-decoration: underline;
      cursor: pointer;
      background: none;
      border: none;
      padding: 0;
    }
    .bypass-link:hover {
      color: #9CA3AF;
    }
  `;
  shadow.appendChild(style);

  // Overlay HTML structure
  const container = document.createElement("div");
  container.className = "overlay-container";
  container.innerHTML = `
    <div class="card">
      <div class="shield-icon">
        <svg viewBox="0 0 24 24">
          <path d="M12 2L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-3zm0 18c-3.75-1-6.5-4.88-6.5-9V6.3l6.5-2.17 6.5 2.17V11c0 4.12-2.75 8-6.5 9z"/>
          <path d="M11 15h2v2h-2zm0-8h2v6h-2z"/>
        </svg>
      </div>
      <h1>Website Access Blocked</h1>
      <div class="subtitle">PhishBlock has flagged this page as highly suspicious (Threat Score: ${score}/100)</div>
      
      <div class="indicators-box">
        <div class="indicators-box-title">Detection Indicators</div>
        <ul class="indicators-list">
          ${indicators.map(ind => `<li>${ind}</li>`).join("")}
        </ul>
      </div>

      <div class="memo-callout">
        <strong>⚠️ CRITICAL ALERT:</strong> BIUST ICT will never request your password, MFA approval, or credential confirmation via email or external links.
      </div>

      <div class="btn-group">
        <button id="go-back-btn" class="btn btn-primary">Go Back to Safety</button>
      </div>
      
      <button id="dev-bypass-btn" class="bypass-link">Proceed anyway (Developer Bypass)</button>
    </div>
  `;
  shadow.appendChild(container);

  // Focus trap inside Shadow DOM
  const goBackBtn = shadow.getElementById("go-back-btn");
  const devBypassBtn = shadow.getElementById("dev-bypass-btn");

  goBackBtn.focus();

  // Go Back logic
  goBackBtn.addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close(); // Close tab if no history
      // Fallback redirect
      window.location.href = "about:blank";
    }
  });

  // Developer bypass logic
  devBypassBtn.addEventListener("click", () => {
    if (confirm("WARNING: Bypassing this safety alert will expose your environment to potential credential theft or session hijack. Do you want to proceed for development purposes?")) {
      sessionStorage.setItem("phishblock_bypass", "true");
      // Remove overlay and restore scroll
      host.remove();
      document.body.style.overflow = "";
      console.warn("[PhishBlock] User bypassed threat overlay.");
      
      // Update badge to "bypassed" warning status
      reportStatus(score, "suspicious", ["Developer Bypass Executed"]);
    }
  });

  // Handle keyboard events to trap focus and prevent page interactions
  const handleKeydown = (e) => {
    if (e.key === "Tab") {
      if (shadow.activeElement === goBackBtn) {
        devBypassBtn.focus();
        e.preventDefault();
      } else {
        goBackBtn.focus();
        e.preventDefault();
      }
    }
    // Block typical bypass hotkeys
    if (e.key === "Escape") {
      e.preventDefault();
    }
  };

  window.addEventListener("keydown", handleKeydown, true);
}

/**
 * PhishBlock - Popup Controller
 * Connects the UI to background state and handles reporting.
 */

document.addEventListener("DOMContentLoaded", () => {
  // UI Elements
  const statusCard = document.getElementById("status-card");
  const statusBadge = document.getElementById("status-badge");
  const scoreNumber = document.getElementById("score-number");
  const tabDomain = document.getElementById("tab-domain");
  const detailsSection = document.getElementById("details-section");
  const indicatorList = document.getElementById("indicator-list");
  const reportBtn = document.getElementById("report-btn");

  let activeTabUrl = "";
  let activeTabTitle = "";
  let activeTabScore = 0;
  let activeTabIndicators = [];

  // 1. Get the current active tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length === 0) return;
    const tab = tabs[0];
    activeTabUrl = tab.url;
    activeTabTitle = tab.title || "Unknown Title";

    // Display hostname or protocol
    try {
      const urlObj = new URL(activeTabUrl);
      if (urlObj.protocol.startsWith("http")) {
        tabDomain.textContent = urlObj.hostname;
      } else {
        tabDomain.textContent = `${urlObj.protocol}//`;
        updateUItoSafe(); // System/Extension pages are safe
        return;
      }
    } catch (e) {
      tabDomain.textContent = "Unknown Domain";
      updateUItoSafe();
      return;
    }

    // 2. Fetch computed threat status from background worker
    chrome.runtime.sendMessage(
      { action: "getTabThreatStatus", tabId: tab.id },
      (statusData) => {
        if (chrome.runtime.lastError) {
          console.warn("[PhishBlock] Could not fetch threat status:", chrome.runtime.lastError);
          updateUItoSafe();
          return;
        }

        if (statusData) {
          updateUI(statusData);
        } else {
          // If no state has been saved yet, default to scanning/safe
          updateUItoSafe();
        }
      }
    );
  });

  /**
   * Updates the popup dashboard values and class states.
   */
  function updateUI(data) {
    activeTabScore = data.score || 0;
    activeTabIndicators = data.indicators || [];

    // Reset card classes
    statusCard.className = "dashboard-card";
    
    // Set UI depending on risk level
    if (data.riskLevel === "malicious") {
      statusCard.classList.add("state-malicious");
      statusBadge.textContent = "Threat Detected";
    } else if (data.riskLevel === "suspicious") {
      statusCard.classList.add("state-suspicious");
      statusBadge.textContent = "Suspicious";
    } else {
      statusCard.classList.add("state-safe");
      statusBadge.textContent = "Safe";
    }

    // Set numbers
    scoreNumber.textContent = activeTabScore;

    // Build indicators list
    if (activeTabIndicators.length > 0) {
      indicatorList.innerHTML = "";
      activeTabIndicators.forEach(ind => {
        const li = document.createElement("li");
        li.textContent = ind;
        indicatorList.appendChild(li);
      });
      detailsSection.style.display = "block";
    } else {
      detailsSection.style.display = "none";
    }
  }

  /**
   * Fallback default safe state.
   */
  function updateUItoSafe() {
    statusCard.className = "dashboard-card state-safe";
    statusBadge.textContent = "Safe";
    scoreNumber.textContent = "0";
    detailsSection.style.display = "none";
  }

  // 3. Formulate and launch the mailto reporting link
  reportBtn.addEventListener("click", () => {
    const to = "icthelpdesk@biust.ac.bw";
    const subject = encodeURIComponent("[PHISHING REPORT] Suspicious Office 365/BIUST Page Detected");
    
    const indicatorsStr = activeTabIndicators.length > 0 
      ? activeTabIndicators.map(ind => `- ${ind}`).join("\r\n")
      : "- (None detected / Manual user override)";

    const body = encodeURIComponent(
      `Hello BIUST ICT Help Desk,\r\n\r\n` +
      `I am reporting a suspicious page detected by the PhishBlock Chrome Extension.\r\n\r\n` +
      `URL: ${activeTabUrl}\r\n` +
      `Title: ${activeTabTitle}\r\n` +
      `Calculated Threat Score: ${activeTabScore}/100\r\n\r\n` +
      `Indicators Triggered:\r\n${indicatorsStr}\r\n\r\n` +
      `Regards,\r\n[User]`
    );

    const mailtoUrl = `mailto:${to}?subject=${subject}&body=${body}`;
    
    // Programmatically trigger mailto redirect
    chrome.tabs.create({ url: mailtoUrl }, (tab) => {
      // Close the mailto tab after a brief delay if it opened as a tab, or just let it close
      setTimeout(() => {
        if (tab && tab.id) {
          chrome.tabs.remove(tab.id);
        }
      }, 1000);
    });
  });
});

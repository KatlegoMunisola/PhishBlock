/**
 * PhishBlock - Background Service Worker
 * Handles domain validation, lookalike detection, and state management.
 */

// Legitimate domains whitelist
const WHITELIST = [
  "microsoftonline.com",
  "office.com",
  "microsoft.com",
  "biust.ac.bw"
];

// Protected brands for lookalike detection
const PROTECTED_BRANDS = [
  "microsoft",
  "office",
  "outlook",
  "biust",
  "microsoftonline",
  "paypal"
];

// Keywords that indicate Microsoft/Office365/BIUST context
const BRAND_KEYWORDS = [
  "microsoft",
  "office365",
  "outlook",
  "biust"
];

/**
 * Computes the Levenshtein distance between two strings.
 */
function getLevenshteinDistance(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Extracts the second-level domain (SLD) or main domain name of a hostname.
 * Handles common double TLDs (e.g. ac.bw).
 */
function getSecondLevelDomain(hostname) {
  const parts = hostname.toLowerCase().split('.');
  if (parts.length < 2) return hostname;
  
  // Double TLD list
  const lastTwo = parts.slice(-2).join('.');
  const doubleTlds = ["ac.bw", "co.uk", "co.za", "com.br", "gov.bw", "org.bw"];
  
  if (doubleTlds.includes(lastTwo)) {
    if (parts.length >= 3) {
      return parts[parts.length - 3];
    }
  }
  return parts[parts.length - 2];
}

/**
 * Checks if a hostname is on the whitelist (including subdomains).
 */
function isWhitelisted(hostname) {
  const host = hostname.toLowerCase();
  return WHITELIST.some(domain => {
    return host === domain || host.endsWith("." + domain);
  });
}

/**
 * Validates a URL and returns detection parameters.
 */
function validateDomain(urlStr) {
  try {
    const url = new URL(urlStr);
    // Ignore non-http(s) protocols like chrome://, file://, etc.
    if (!url.protocol.startsWith("http")) {
      return {
        isWhitelisted: true, // Safe by exclusion
        isLookalike: false,
        isSuspiciousKeyword: false,
        matchedBrand: null,
        hostname: url.hostname
      };
    }

    const hostname = url.hostname;
    
    // 1. Direct Whitelist check
    if (isWhitelisted(hostname)) {
      return {
        isWhitelisted: true,
        isLookalike: false,
        isSuspiciousKeyword: false,
        matchedBrand: null,
        hostname
      };
    }

    // 2. Substring matching of brand keywords
    const isSuspiciousKeyword = BRAND_KEYWORDS.some(keyword => hostname.includes(keyword));

    // 3. Levenshtein lookalike detection
    const sld = getSecondLevelDomain(hostname);
    let isLookalike = false;
    let matchedBrand = null;

    for (const brand of PROTECTED_BRANDS) {
      const distance = getLevenshteinDistance(sld, brand);
      // If edit distance is 1 or 2, it is highly likely typosquatting
      if (distance > 0 && distance <= 2) {
        isLookalike = true;
        matchedBrand = brand;
        break;
      }
    }

    return {
      isWhitelisted: false,
      isLookalike,
      isSuspiciousKeyword,
      matchedBrand,
      hostname
    };
  } catch (e) {
    return {
      isWhitelisted: true,
      isLookalike: false,
      isSuspiciousKeyword: false,
      matchedBrand: null,
      hostname: ""
    };
  }
}

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "checkDomain") {
    const validation = validateDomain(request.url);
    sendResponse(validation);
  } else if (request.action === "updateTabThreatStatus") {
    const tabId = sender.tab ? sender.tab.id : request.tabId;
    if (tabId) {
      const statusData = {
        url: request.url,
        title: request.title,
        score: request.score,
        riskLevel: request.riskLevel,
        indicators: request.indicators,
        isWhitelisted: request.isWhitelisted,
        timestamp: Date.now()
      };
      
      chrome.storage.local.set({ [`tabStatus_${tabId}`]: statusData }, () => {
        // Also update extension badge
        updateBadge(tabId, request.riskLevel, request.score);
        sendResponse({ success: true });
      });
      return true; // Keep message channel open for async response
    }
  } else if (request.action === "getTabThreatStatus") {
    chrome.storage.local.get(`tabStatus_${request.tabId}`, (data) => {
      sendResponse(data[`tabStatus_${request.tabId}`] || null);
    });
    return true;
  }
});

// Update the extension badge according to risk level
function updateBadge(tabId, riskLevel, score) {
  let text = "";
  let color = "#10B981"; // Green (Safe)

  if (riskLevel === "malicious") {
    text = "HIGH";
    color = "#EF4444"; // Red
  } else if (riskLevel === "suspicious") {
    text = "WARN";
    color = "#F59E0B"; // Amber
  } else if (score > 0) {
    text = score.toString();
    color = "#3B82F6"; // Blue
  }

  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

// Clean up tab status on close
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tabStatus_${tabId}`);
});

// Clean up state when a tab URL updates or resets
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    chrome.storage.local.remove(`tabStatus_${tabId}`, () => {
      chrome.action.setBadgeText({ tabId, text: "" });
    });
  }
});

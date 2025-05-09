// Global variables
let apiURL = 'http://localhost:5000/api';
let cachedResults = {};

// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishGuard extension installed');
  // Initialize storage
  chrome.storage.local.set({
    scanHistory: [],
    settings: {
      autoScan: true,
      notifyOnDetection: true,
      highRiskThreshold: 75,
      mediumRiskThreshold: 50
    }
  });
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'analyzeURL') {
    analyzeURL(message.url)
      .then(result => {
        sendResponse({ success: true, result });
        // Cache the result
        cachedResults[message.url] = {
          result,
          timestamp: Date.now()
        };
        // Update scan history
        updateScanHistory(message.url, result);
      })
      .catch(error => {
        console.error('Analysis error:', error);
        sendResponse({ success: false, error: error.message });
      });
    return true; // Keep the message channel open for async response
  }

  if (message.action === 'getCachedResult') {
    const cachedResult = cachedResults[message.url];
    if (cachedResult && (Date.now() - cachedResult.timestamp < 3600000)) { // Cache valid for 1 hour
      sendResponse({ success: true, cached: true, result: cachedResult.result });
    } else {
      sendResponse({ success: false, cached: false });
    }
    return true;
  }

  if (message.action === 'getSettings') {
    chrome.storage.local.get('settings', (data) => {
      sendResponse({ success: true, settings: data.settings });
    });
    return true;
  }

  if (message.action === 'updateSettings') {
    chrome.storage.local.set({ settings: message.settings }, () => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.action === 'getScanHistory') {
    chrome.storage.local.get('scanHistory', (data) => {
      sendResponse({ success: true, history: data.scanHistory || [] });
    });
    return true;
  }

  if (message.action === 'clearScanHistory') {
    chrome.storage.local.set({ scanHistory: [] }, () => {
      sendResponse({ success: true });
    });
    return true;
  }
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Check if autoScan is enabled
    chrome.storage.local.get('settings', (data) => {
      if (data.settings && data.settings.autoScan) {
        const url = new URL(tab.url);
        // Only analyze HTTP/HTTPS URLs (skip chrome:// pages, etc.)
        if (url.protocol === 'http:' || url.protocol === 'https:') {
          // Check if we have a cached result first
          const cachedResult = cachedResults[tab.url];
          if (cachedResult && (Date.now() - cachedResult.timestamp < 3600000)) {
            // Use cached result if less than 1 hour old
            handleResult(tabId, tab.url, cachedResult.result);
          } else {
            // Otherwise perform a new analysis
            analyzeURL(tab.url)
              .then(result => {
                cachedResults[tab.url] = {
                  result,
                  timestamp: Date.now()
                };
                handleResult(tabId, tab.url, result);
                updateScanHistory(tab.url, result);
              })
              .catch(error => console.error('Auto-scan error:', error));
          }
        }
      }
    });
  }
});

// Function to analyze a URL
async function analyzeURL(url) {
  try {
    const response = await fetch(`${apiURL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('API Request failed:', error);
    throw error;
  }
}

// Function to handle scan results
function handleResult(tabId, url, result) {
  // Get settings to check notification threshold
  chrome.storage.local.get('settings', (data) => {
    const settings = data.settings || {};

    // Update the extension icon based on risk level
    updateIcon(tabId, result.risk_level);

    // Show notification if enabled and risk is high
    if (settings.notifyOnDetection &&
        result.confidence_score >= (settings.highRiskThreshold || 75)) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '⚠️ Phishing Warning',
        message: `This site (${new URL(url).hostname}) has been flagged as potentially dangerous with ${result.confidence_score}% risk.`
      });
    }
  });
}

// Function to update the extension icon based on risk level
function updateIcon(tabId, riskLevel) {
  let iconPath;

  switch (riskLevel) {
    case 'High Risk':
      iconPath = 'icons/icon_red.png';
      break;
    case 'Medium Risk':
      iconPath = 'icons/icon_yellow.png';
      break;
    case 'Low Risk':
      iconPath = 'icons/icon_blue.png';
      break;
    case 'Safe':
      iconPath = 'icons/icon_green.png';
      break;
    default:
      iconPath = 'icons/icon48.png';
  }

  chrome.action.setIcon({
    tabId: tabId,
    path: iconPath
  });
}

// Function to update scan history
function updateScanHistory(url, result) {
  chrome.storage.local.get('scanHistory', (data) => {
    const history = data.scanHistory || [];

    // Add new entry to the beginning of the array
    history.unshift({
      url,
      domain: new URL(url).hostname,
      timestamp: Date.now(),
      confidenceScore: result.confidence_score,
      riskLevel: result.risk_level
    });

    // Keep only the latest 100 entries
    const trimmedHistory = history.slice(0, 100);

    chrome.storage.local.set({ scanHistory: trimmedHistory });
  });
}
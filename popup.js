// popup.js
document.addEventListener('DOMContentLoaded', function() {
  const currentUrlElement = document.getElementById('currentUrl');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const loading = document.getElementById('loading');
  const statusMessages = document.getElementById('statusMessages');
  const resultContent = document.getElementById('resultContent');

  let currentUrl = '';

  // Get current active tab URL when popup opens
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs && tabs[0] && tabs[0].url) {
      currentUrl = tabs[0].url;
      currentUrlElement.textContent = currentUrl;
      analyzeBtn.disabled = false;
    } else {
      currentUrlElement.textContent = 'No URL detected';
      analyzeBtn.disabled = true;
    }
  });

  analyzeBtn.addEventListener('click', analyzeUrl);

  async function analyzeUrl() {
    if (!currentUrl) return;

    // Reset UI
    statusMessages.innerHTML = '';
    resultContent.style.display = 'none';
    resultContent.innerHTML = '';
    loading.style.display = 'block';
    analyzeBtn.disabled = true;

    try {
      // Add initial status using HTML entities instead of Unicode emojis
      addStatusMessage('Starting analysis...', 'primary');

      // Start analysis
      const response = await fetch('http://localhost:8000/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: currentUrl })
      });

      if (!response.ok) {
        throw new Error(`Server responded with status: ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      while(true) {
        const { done, value } = await reader.read();
        if(done) break;

        const chunk = decoder.decode(value);
        const messages = chunk.split('\n').filter(m => m);

        for (const message of messages) {
          try {
            const data = JSON.parse(message);
            if(data.status) {
              // Convert emoji text to HTML entities or simple text
              const cleanStatus = data.status
                .replace("🔍", "")
                .replace("🛡️", "")
                .replace("🤖", "")
                .replace("🚀", "");
              addStatusMessage(cleanStatus, 'info');
            }
            if(data.result) {
              showFinalResult(data.result);
            }
          } catch (parseError) {
            console.error('Error parsing JSON:', parseError);
          }
        }
      }
    } catch (error) {
      console.error('Error:', error);
      addStatusMessage(`Error: ${error.message}`, 'danger');

      resultContent.style.display = 'block';
      resultContent.innerHTML = `
        <div class="result-header">
          <span class="icon-error"></span>
          <h3>Analysis Failed</h3>
        </div>
        <p>We encountered an error while analyzing this URL. Please try again later or check your connection.</p>
      `;
    } finally {
      analyzeBtn.disabled = false;
    }
  }

  function addStatusMessage(message, type = 'info') {
    const statusItem = document.createElement('div');
    statusItem.className = 'status-item';

    // Add border color based on message type
    if (type === 'danger') {
      statusItem.style.borderLeft = '3px solid var(--danger)';
    } else if (type === 'warning') {
      statusItem.style.borderLeft = '3px solid var(--warning)';
    } else if (type === 'success') {
      statusItem.style.borderLeft = '3px solid var(--success)';
    } else {
      statusItem.style.borderLeft = '3px solid var(--primary)';
    }

    statusItem.textContent = message;
    statusMessages.appendChild(statusItem);

    // Auto-scroll to bottom
    statusMessages.scrollTop = statusMessages.scrollHeight;
  }

  function showFinalResult(result) {
    // Extract confidence score - attempt to parse percentage if it's in text form
    let rawScore = result.final_score;
//    alert(rawScore);
    let parsedScore = parseFloat(rawScore.toString().replace(/[^\d.]/g, ''));

    if (isNaN(parsedScore)) {
    console.error('Invalid confidence score format:', rawScore);
    addStatusMessage('Unable to read confidence score from server.', 'danger');
    loading.style.display = 'none';
    return;
    }

    confidenceScore = parsedScore;
    console.log(confidenceScore);
//    // Normalize to 0-1 range if needed
//    if (confidenceScore > 1) {
//      confidenceScore = confidenceScore / 100;
//    }

    // Format as percentage
    const scoreDisplay = `${Math.round(confidenceScore)}%`;
    // Determine safety level and icon (using CSS classes instead of emojis)
    let safetyLevel, iconClass, scoreClass;

    if (confidenceScore < 25) {
      safetyLevel = "Safe";
      iconClass = "icon-safe";
      scoreClass = "score-safe";
    } else if (confidenceScore < 60) {
      safetyLevel = "Suspicious";
      iconClass = "icon-warning";
      scoreClass = "score-warning";
    } else {
      safetyLevel = "Dangerous";
      iconClass = "icon-danger";
      scoreClass = "score-danger";
    }

    // Show the results container
    resultContent.style.display = 'block';

    resultContent.innerHTML = `
      <div class="result-header">
        <h3>Analysis Complete</h3>
        <span class="score ${scoreClass}" style="margin-left: auto;">${safetyLevel}</span>
      </div>

      <div class="score-container">
        <div class="big-score ${scoreClass}">
          ${scoreDisplay}
        </div>
        <div class="score-label">Phishing Confidence</div>
      </div>

      <div class="recommendation">
        <strong>${getSecuritySummary(safetyLevel)}</strong>
        <p>${getRecommendation(safetyLevel)}</p>
      </div>
    `;

    // Add status message about completion (without emoji)
    addStatusMessage(`Analysis complete: ${safetyLevel}`,
      safetyLevel === "Safe" ? "success" :
      safetyLevel === "Suspicious" ? "warning" : "danger");

    // Hide the loading spinner but keep status messages visible
    loading.style.display = 'none';
  }

  function getSecuritySummary(safetyLevel) {
    switch(safetyLevel) {
      case "Safe":
        return "This website appears to be legitimate";
      case "Suspicious":
        return "This website shows some concerning patterns";
      case "Dangerous":
        return "This website is likely fraudulent";
      default:
        return "Analysis inconclusive";
    }
  }

  function getRecommendation(safetyLevel) {
    switch(safetyLevel) {
      case "Safe":
        return "Our analysis suggests this is a legitimate website, but always stay vigilant online.";
      case "Suspicious":
        return "Proceed with caution and avoid sharing sensitive information on this site.";
      case "Dangerous":
        return "We strongly recommend not visiting this site or sharing any information.";
      default:
        return "Always verify the legitimacy of websites before sharing sensitive information.";
    }
  }
});
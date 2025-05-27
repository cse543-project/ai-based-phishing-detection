# PhishGuard

PhishGuard is a Chrome extension that uses AI and VirusTotal to detect phishing websites in real-time.

## GitHub

Public repository: [https://github.com/cse543-project/ai-based-phishing-detection](https://github.com/cse543-project/ai-based-phishing-detection)

## Table of Contents

* [Installation](#installation)
* [Usage](#usage)
* [Features](#features)
* [Screenshots](#screenshots)
* [Backend API](#backend-api)
* [Development](#development)
* [Configuration](#configuration)
* [Contributing](#contributing)
* [License](#license)

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/YourUsername/PhishGuard.git
   cd PhishGuard
   ```
2. **Install backend dependencies**:

   ```bash
   pip install -r requirements.txt
   ```
3. **Run the backend API**:

   ```bash
   python backend_api.py
   ```
4. **Load the extension in Chrome**:

   * Go to `chrome://extensions`
   * Enable **Developer mode**
   * Click **Load unpacked** and select the project folder

## Usage

1. Click the PhishGuard icon in the Chrome toolbar.
2. Click **Analyze This Page** to scan the current URL.
3. View the risk level and detailed recommendation in the popup.

## Features

* Real-time URL analysis using AI (Llama) and VirusTotal
* Automatic background scanning of every page load
* Customizable thresholds for high/medium risk alerts
* Local caching of scan results to reduce repeated API calls

## Screenshots

![Safe Site Analysis](screenshots/safe_analysis.png)
![Malicious Site Detection](screenshots/malicious_detection.png)

> **Note:** Include a screenshot named `malicious_detection.png` in `screenshots/` to show a malicious URL being flagged.

## Backend API

The backend is built with FastAPI and streams analysis results:

* **Base URL:** `http://localhost:8000`
* **Endpoint:** `POST /analyze`

  ```json
  {
    "url": "https://example.com"
  }
  ```
* **Response:** Streamed NDJSON messages with intermediate statuses and a final confidence score.

## Development

* To change the API port or host, update the endpoint in `popup.js` (`fetch('http://localhost:8000/analyze')`) or in `background.js` (`apiURL`).
* UI customization is available in `popup.html` and `popup.css`.
* Business logic lives in `popup.js`, `background.js`, and `backend_api.py`.

## Configuration

Stored in Chrome `chrome.storage.local`:

* `autoScan` (boolean): perform automatic scanning on page load.
* `notifyOnDetection` (boolean): show Chrome notification on high-risk detection.
* `highRiskThreshold` (number, 0–100): score above which a notification is shown.
* `mediumRiskThreshold` (number, 0–100): score above which the icon turns yellow.

## Contributing

1. Fork this repository
2. Create a branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add new feature"`
4. Push to your branch: `git push origin feature/my-feature`
5. Open a Pull Request

## Authors
1. Sai Teja Alasyam
2. Akash Sateesha
3. Vishal Lakshmi Narayanan
4. Aarya Choudhary
5. Aditya Rallapalli
6. Ajita Bhardwaj
7. Lekshman Babu Devendra Babu
8. Maanesh Mohanraj


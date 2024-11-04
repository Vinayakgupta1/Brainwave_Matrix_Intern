# Phishing Link Scanner

A Python-based phishing link scanner designed to analyze URLs for common phishing indicators. The tool uses heuristics to detect suspicious patterns in URLs, webpage content, and form actions.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [Phishing Detection Details](#phishing-detection-details)
- [Sample Phishing Databases](#sample-phishing-databases)
---

## Features

- Detects suspicious keywords in URLs (e.g., `login`, `verify`, `account`)
- Identifies shortened URLs often used in phishing attacks
- Analyzes webpage content to find unusual forms that might collect sensitive data

## Requirements

To run this project, you need:
- Python 3.6 or higher
- Libraries: `tldextract`, `tkinter`


## Setup

1. **Clone the repository**:

    ```bash
    git clone https://github.com/Vinayakgupta1/Brainwave_Matrix_Intern/Phishing-Link-Scanner.git
    cd Phishing-Link-Scanner
    ```

2. **Install Dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the Script**:

    ```bash
    python phishing-link-scanner.py
    ```

2. **Enter a URL** when prompted to analyze it:

    ```plaintext
    Enter a URL to analyze: https://example-phishing-site.com
    ```

3. **Interpret the Results**:

    The scanner will print warnings if it finds suspicious indicators, such as phishing-related keywords in the URL, forms collecting data insecurely, or if the URL is flagged as malicious on VirusTotal (if the API key is set up).

## Phishing Detection Details

This scanner detects phishing indicators through the following methods:

- **URL Structure Check**: Looks for phishing-related keywords (e.g., `login`, `account`, `verify`), often present in phishing links.
- **Shortened URL Detection**: Warns if a shortened URL (e.g., `bit.ly`, `tinyurl`) is detected, as these are frequently used in phishing campaigns.
- **Form Action Check**: Analyzes webpage forms for insecure form actions (e.g., forms not using HTTPS for data submission).

## Sample Phishing Databases

- Phisning Link Website: https://openphish.com/
- Phishing Link Database: https://github.com/mitchellkrogza/Phishing.Database

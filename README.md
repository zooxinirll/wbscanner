# wbscanner
![wbscanner](https://github.com/user-attachments/assets/9d7fc3ab-3152-46c4-a1d1-a2458a870bc6)


**WBScanner** is a Python-based security scanner designed for assessing various web application vulnerabilities. It aims to identify potential security flaws such as Host Header Injection, CORS misconfiguration, Clickjacking vulnerabilities, HTTP Request Smuggling, and unsafe HTTP methods in web applications. The scanner is designed to be easy to use, with support for scanning individual URLs or reading from an input file containing multiple URLs. It uses a range of techniques to test these vulnerabilities and reports the results with color-coded output for easier interpretation.

## Key Features:

• Host Header Injection Detection: Tests for the presence of reflected payloads in Host and X-Forwarded-Host headers.

• CORS Misconfiguration Detection: Checks for insecure Cross-Origin Resource Sharing (CORS) configurations allowing malicious origins.

• Clickjacking Detection: Identifies websites that lack proper defenses against clickjacking attacks.

• HTTP Request Smuggling Detection: Analyzes the potential for request smuggling vulnerabilities.

• HTTP Methods Detection: Checks for unsafe HTTP methods like PUT, DELETE, TRACE, and CONNECT.

• Randomized User-Agent: For evading basic anti-bot measures.

• Interactive User Interface: Uses progress bars and color-coded outputs to provide clear scan results.

• Scan Results Export: Allows users to save the results to a text file for later analysis.


## Requirements

- Python 3.6+
- Required Python packages:

  - `requests`
  - `alive-progress`
  - `termcolor`
  - `pyfiglet`

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/zooxinirll/wbscanner.git
    ```
2. Navigate to the directory:
    ```bash
    cd wbscanner 
    ```
3. Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

## Run

  ```bash
    python wbscanner.py
  ```

## Usage

*Scanning a Single URL :* To scan a single target URL, run the script and provide the URL when prompted

*Scanning Multiple URLs from a File :* To scan a list of URLs stored in a text file, provide the file name when prompted

*The input file should contain one URL per line, like so:*

  ```bash
    http://example.com
    https://example2.com
  ```
     


## 🌐 Connect With Me
<p align="center"> <a href="https://github.com/zooxinirll" target="_blank"> <img src="https://img.shields.io/badge/GitHub-000?style=for-the-badge&logo=github&logoColor=white" /> </a> <a href="https://www.instagram.com/h3r.10c4lh0st.07?igsh=MTRqcGNsdmN3a2FyaA==" target="_blank"> <img src="https://img.shields.io/badge/Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white" /> </a></p>

### 🧠 Let's Collaborate
I'm always open to discussing new projects, innovative ideas, and opportunities. Feel free to reach out via my social platforms!


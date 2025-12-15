# Phishing-Incident-Investigation-SOC-Simulation-TryHackMe-
The goal of this lab was to simulate a real-world phishing incident from the perspective of a Security Operations Center (SOC) analyst. I analyzed a suspicious email, identified malicious indicators, determined impact, and documented an appropriate incident response.
*Role:** Security Operations Center (SOC) Analyst  
> **Environment:** Simulated Enterprise SOC  
> **Attack Type:** Email-Based Phishing  
> **Frameworks Used:** MITRE ATT&CK  
> **Platform:** TryHackMe  

---

## 📌 Objective

This lab simulates a **real-world phishing incident** investigated from the perspective of a SOC analyst.  
The objective was to identify, analyze, classify, and respond to a phishing email using standard SOC workflows and threat intelligence principles.

This project demonstrates my ability to:
- Detect phishing attacks
- Analyze email artifacts and headers
- Identify Indicators of Compromise (IOCs)
- Assess organizational risk
- Map attacker behavior to MITRE ATT&CK
- Recommend mitigation and prevention strategies

---

## 🧠 SOC Analyst Perspective

This investigation was conducted using **real SOC methodology**, not just tool execution.

Key analyst behaviors demonstrated:
- Alert validation instead of blind acceptance
- Threat context evaluation
- False-positive reduction
- User and business impact assessment
- Threat behavior mapping using MITRE ATT&CK

This mirrors how phishing incidents are handled in real enterprise SOC environments.

---

## 🧰 Tools & Concepts Used

| Tool / Concept | Purpose |
|----------------|--------|
| Email Header Analysis | Identify spoofing and sender anomalies |
| URL Analysis | Detect malicious or deceptive links |
| Domain Reputation Analysis | Evaluate attacker infrastructure |
| IOC Extraction | Capture attack fingerprints |
| SOC Triage Workflow | Classify and prioritize incidents |
| MITRE ATT&CK | Map adversary behavior to known techniques |

---

## 📂 Investigation Workflow

### 1️⃣ Alert Intake & Initial Review

- Received a phishing alert triggered by a suspicious email
- Reviewed sender address, subject line, and message content
- Identified **social engineering techniques** designed to pressure the user into action

**Evidence:**
[INSERT IMAGE: Initial phishing alert or email overview]

<img width="1920" height="1000" alt="phising email splunk" src="https://github.com/user-attachments/assets/0a444214-4acd-4530-8366-d88f233b2304" />



---

### 2️⃣ Email Header Analysis

- Analyzed full email headers to determine:
  - True sender IP address 67.199.248.11
  - SPF / DKIM / DMARC authentication results
  - Signs of spoofing or relay abuse 
- Identified mismatches between the displayed sender and the actual sending domain

**Evidence:**
[INSERT IMAGE: Email header analysis showing anomalies]

<img width="1906" height="1003" alt="phishing email firewall log alert classification high" src="https://github.com/user-attachments/assets/7a1e1546-e6fc-454f-aafc-5e7f02765871" />


---

### 3️⃣ URL & Payload Analysis

- Extracted embedded links from the email body
- Analyzed URLs for:
  - Typosquatting
  - Recently registered domains
  - Credential harvesting indicators
- Determined malicious intent based on domain reputation and URL structure

**Evidence:**
[INSERT IMAGE: URL analysis results]

<img width="1916" height="989" alt="Vm tryDetectThis URK analyzer Malicous" src="https://github.com/user-attachments/assets/82ed7115-4972-411d-a680-5c00569e556b" />


---

### 4️⃣ Indicator of Compromise (IOC) Identification

Extracted and documented IOCs including:
- Malicious sender email address urgents@amazon.biz
- Suspicious domain(s) .biz
- Embedded phishing URL(s) http://bit.ly/3sHkX3da12340

These indicators can be leveraged for future detection rules and blocklists.

**Evidence:**
[INSERT IMAGE: IOC extraction evidence]

<img width="1920" height="995" alt="Firewall splunk logs ip of hacker payload and URL" src="https://github.com/user-attachments/assets/e13e6f87-f17a-4df6-b6b4-5ae6f888d129" />


---

### 5️⃣ Impact Assessment

- Evaluated whether the phishing email was:
  - Delivered
  - Opened
  - Clicked
- Assessed potential impact to:
  - User credentials
  - Internal systems
  - Organizational security posture

**Evidence:**
[INSERT IMAGE: User interaction or delivery evidence]

<img width="1906" height="1003" alt="phishing email firewall log alert classification high" src="https://github.com/user-attachments/assets/33ce55e8-74e6-4348-b882-8b86f1395de7" />



---

### 6️⃣ Incident Classification & Severity

- **Incident Type:** Phishing  
- **Attack Vector:** Email-based social engineering  
- **Severity:** Medium → High (dependent on user interaction)  
- **Risk:** Credential compromise potential  

**Evidence:**
[INSERT IMAGE: SOC case classification view]

<img width="1915" height="998" alt="case report final" src="https://github.com/user-attachments/assets/3560c214-967c-4dd8-9628-1b4a411c1458" />



---

## 🚨 Final Verdict

✅ **Confirmed Phishing Attempt**

The email exhibited multiple phishing indicators:
- Deceptive sender identity
- Malicious embedded link(s)
- Psychological manipulation tactics

No evidence of lateral movement or endpoint compromise was observed during this investigation.


## 🛠️ SOC Response Recommendations

### Immediate Actions
- Block sender domain and IP address
- Add malicious URLs to organizational blocklists
- Notify potentially affected users

### Preventative Measures
- Strengthen email filtering rules
- Conduct phishing awareness training
- Enforce Multi-Factor Authentication (MFA)

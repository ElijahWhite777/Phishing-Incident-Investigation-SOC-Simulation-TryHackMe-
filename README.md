# Phishing-Incident-Investigation-SOC-Simulation-TryHackMe-
**Role:** Security Operations Center (SOC) Analyst  
> **Environment:** Simulated Enterprise SOC  
> **Attack Type:** Email-Based Phishing  
> **Frameworks Used:** MITRE ATT&CK & NIST Cybersecurity Framework (CSF)  
> **Platform:** TryHackMe  

---

## 📌 Objective

The goal of this lab was to simulate a **real-world phishing incident** from the perspective of a SOC analyst.  
The investigation focused on identifying malicious email activity, validating indicators of compromise (IOCs), assessing user impact, and documenting a complete incident response aligned with industry frameworks.

This project demonstrates my ability to:
- Detect and analyze phishing attacks
- Investigate email headers, URLs, and payloads
- Identify and document IOCs
- Assess organizational risk and user impact
- Map attacker behavior to **MITRE ATT&CK**
- Align incident handling to the **NIST CSF lifecycle**
- Recommend effective remediation and prevention actions

---

## 🧠 SOC Analyst Perspective

This investigation followed **real SOC methodology**, not just tool usage.

Key analyst behaviors demonstrated:
- Alert validation prior to classification  
- Threat context evaluation  
- Reduction of false positives  
- User and business impact assessment  
- Mapping attacker techniques (MITRE) to response lifecycle stages (NIST)

This mirrors how phishing incidents are handled in enterprise SOC environments.

---

## 🧰 Tools & Concepts Used

| Tool / Concept | Purpose |
|----------------|--------|
| Email Header Analysis | Identify spoofing, relay abuse, and sender anomalies |
| URL Analysis | Detect malicious or deceptive links |
| Domain Reputation Analysis | Evaluate attacker infrastructure |
| IOC Extraction | Capture attacker fingerprints |
| SOC Triage Workflow | Classify, prioritize, and respond to alerts |
| MITRE ATT&CK | Map adversary behavior |
| NIST CSF | Align detection, response, and improvement |

---

## 📂 Investigation Workflow

### 1️⃣ Alert Intake & Initial Review  
**MITRE:** T1566 – Phishing  
**NIST:** DE.AE – Anomalies & Events

- Received a phishing alert triggered by a suspicious email
- Reviewed sender address, subject line, and email content
- Identified social engineering techniques designed to create urgency and trust

**Evidence:**

<img width="1909" height="1001" alt="email header anomalies" src="https://github.com/user-attachments/assets/0c535ad6-7b49-44f0-b6fc-93b1ed2bdd64" />

---

### 2️⃣ Email Header Analysis  
**MITRE:** T1036 – Masquerading  
**NIST:** DE.CM – Security Continuous Monitoring

- Analyzed full email headers to determine:
  - True sender address: `urgents@amazon.biz`
  - Sending IP: `67.199.248.11`
  - Failed or suspicious SPF/DKIM/DMARC authentication
- Identified domain spoofing:
  - Legitimate Amazon domains use `.com`, not `.biz`

**Evidence:**

<img width="1920" height="1000" alt="phishing email header analysis" src="https://github.com/user-attachments/assets/34be0a3b-cd0c-4eae-b568-e35ad6027526" />

---

### 3️⃣ URL & Payload Analysis  
**MITRE:** T1566 – phishing Link  
**NIST:** DE.AE – Anomalous Activity

- Extracted embedded URLs from the email body
- Analyzed links for:
  - URL shortening abuse
  - Redirection behavior
  - Credential harvesting indicators
- Determined malicious intent based on domain reputation and structure

**Evidence:**

<img width="1916" height="989" alt="malicious URL analysis" src="https://github.com/user-attachments/assets/82ed7115-4972-411d-a680-5c00569e556b" />

---

### 4️⃣ Indicator of Compromise (IOC) Identification  
**MITRE:** T1583 – Acquire Infrastructure  
**NIST:** RS.AN – Analysis

Identified and documented the following IOCs:
- Malicious sender: `urgents@amazon.biz`
- Suspicious TLD: `.biz`
- Malicious URL: `http://bit.ly/3sHkX3da12340`

These IOCs can be used for detection rules and blocklists across security controls.

**Evidence:**

<img width="1906" height="1003" alt="firewall alert showing phishing activity" src="https://github.com/user-attachments/assets/30869c86-24e8-4073-84bd-dd6fb4c0b7f6" />

---

### 5️⃣ Impact Assessment  
**MITRE:** T1071.001 – Web Protocols (Attempted C2)  
**NIST:** ID.RA – Risk Assessment

- Confirmed the phishing email was:
  - Delivered
  - Opened
  - Clicked
- Timeline of activity:
  - **12/15/2025 18:16:48.097** – Email received by user `h.harris`
  - **12/15/2025 18:18:02.097** – Malicious link clicked
- Firewall logs confirmed an attempted outbound TCP connection from:
  - Source IP: `10.20.2.17`
  - Destination: attacker-controlled domain
- Connection was **successfully blocked** by firewall controls
- No lateral movement or additional host communication observed
- EDR would be used in a production environment to validate endpoint integrity

**Evidence:**

<img width="1920" height="1001" alt="phishing email received" src="https://github.com/user-attachments/assets/6f98c609-6c9e-4b59-bbe2-6265d82d8e92" />

<img width="1920" height="1001" alt="blocked TCP connection attempt" src="https://github.com/user-attachments/assets/fee82bd8-7d90-4290-a472-8a887663503e" />

---

### 6️⃣ Incident Classification & Severity  
**NIST:** RS.AN – Analysis | RS.MI – Mitigation

- **Incident Type:** Phishing  
- **Attack Vector:** Email-based social engineering  
- **Severity:** Medium → High  
- **Risk:** Credential compromise potential  

**Evidence:**

<img width="1915" height="998" alt="final incident report" src="https://github.com/user-attachments/assets/3560c214-967c-4dd8-9628-1b4a411c1458" />

---

## 🚨 Final Verdict  
**NIST:** RS.CO – Communications | RC.CO – Closure

✅ **Confirmed Phishing Attempt**

The phishing attempt was successfully detected and contained:
- Firewall controls blocked attacker communication
- No credential compromise confirmed
- No lateral movement or endpoint infection observed
- Escalation was not required due to full containment

---

## 🛠️ SOC Response Recommendations  
**NIST:** RS.MI – Mitigation | PR.AT – Awareness & Training

### Immediate Actions
- Block malicious sender domain and IP
- Add phishing URL to blocklists
- Monitor for repeat activity

### Preventative Measures
- Strengthen email filtering rules
- Conduct targeted phishing awareness training
- Enforce Multi-Factor Authentication (MFA)

---

## 🎯 Why This Matters

This investigation demonstrates:
- Real SOC investigation methodology
- Tactical attacker understanding (MITRE ATT&CK)
- Strategic incident lifecycle alignment (NIST CSF)
- Tier-2 containment and decision-making capability
- Clear, professional incident documentation

# Phishing Investigation SOC Lab

A Python-based SOC automation project for investigating suspicious phishing emails and generating a structured security investigation report.

## Features

- Email and header analysis
- SPF, DKIM and DMARC analysis
- URL, domain, IP and email IOC extraction
- File attachment hash analysis
- VirusTotal threat intelligence
- urlscan.io analysis
- Evidence correlation
- Risk scoring and severity classification
- **AI-assisted phishing assessment and evidence explanations**
- **AI-generated investigation summaries and response recommendations**
- **AI analysis with confidence reporting and identified limitations**
- Automated HTML investigation report
- osTicket incident ticket creation

## Architecture
```
Phishing Email
      ↓
Email Parser
      ↓
Header & Authentication Analysis
      ↓
IOC & Attachment Extraction
      ↓
VirusTotal + urlscan.io
      ↓
Evidence Correlation
      ↓
Risk Scoring
      ↓
AI-Assisted Phishing Assessment
      ↓
SOC Investigation Report
      ↓
osTicket Incident

```

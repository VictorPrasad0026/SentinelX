# 🛡️ SentinelX

## AI-Assisted External Attack Surface Management (ASM) Platform

![Status](https://img.shields.io/badge/status-active%20development-blue)
![Phase](https://img.shields.io/badge/phase-1%20foundation-success)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![Security](https://img.shields.io/badge/focus-Cybersecurity-red)

SentinelX is a modular **External Attack Surface Management (ASM)** platform designed to discover, enrich, analyze, and prioritize internet-facing assets.

The goal of SentinelX is to build an intelligence-driven security platform capable of answering:

> "What assets does an organization expose to the internet, how risky are they, and why?"

Unlike traditional scanners that only identify vulnerabilities, SentinelX focuses on **asset intelligence, relationship mapping, explainable risk scoring, and attack surface visibility**.

---

# 🚀 Vision

The long-term goal is to build an enterprise-style ASM platform combining:

- External asset discovery
- Security intelligence collection
- Infrastructure analysis
- Risk prioritization
- Attack path discovery
- Threat intelligence correlation
- AI-assisted security analysis


Future architecture:

```
                 Organization

                      |

                    Domain

                      |

              Discovery Engine

                      |

        ┌─────────────┴─────────────┐

        ↓                           ↓

 Asset Intelligence          Threat Intelligence

        ↓                           ↓

 Enrichment Engine

                      |

                Risk Engine

                      |

              Asset Knowledge Graph

                      |

             AI Security Analyst

                      |

              Dashboard / API
```

---

# 📌 Current Development Status

## Phase 1 — Asset Intelligence Foundation

Progress:

```
██████████████░░░░░░

~60% Complete
```

Current SentinelX pipeline:

```
Domain

  ↓

Subdomain Discovery

  ↓

Asset Enrichment

  ↓

Security Collectors

  ↓

Risk Engine

  ↓

Asset Graph

  ↓

Security Report
```

---

# ✅ Implemented Features

## 🔎 Asset Discovery

### Subdomain Intelligence

Multi-source discovery:

- Certificate Transparency Logs
- CRT.sh
- CertSpotter
- Recursive DNS discovery
- DNS brute force foundation
- Wildcard detection
- Source tracking


Example:

```
admission.example.com

Source:
CertSpotter

IP:
3.x.x.x
```

---

# 🌐 Domain Intelligence

Collects:

- Domain information
- WHOIS data
- Registrar details
- Nameservers
- DNSSEC status
- IP resolution
- ASN information
- Hosting provider
- Reverse DNS
- TLD analysis


Example:

```
Domain:
example.com

Registrar:
Example Registrar

Infrastructure:
AWS

ASN:
16509
```

---

# 📡 DNS Intelligence

Current support:

- A records
- AAAA records
- MX records
- NS records


Planned:

- TXT
- SPF
- DMARC
- DKIM
- CAA
- SOA
- SRV
- PTR

---

# 🔐 SSL Intelligence

Analyzes:

- Certificate information
- Issuer
- Subject
- TLS version
- Certificate validity
- Expiration status


Example:

```
TLS:
TLS 1.3

Issuer:
Let's Encrypt

Status:
VALID
```

---

# 🖥️ Web Technology Intelligence

Detects:

- Web technologies
- Frameworks
- CMS platforms
- Server information
- Security headers
- Cookies


Security checks:

- HSTS
- CSP
- X-Frame-Options
- X-Content-Type-Options
- Referrer Policy
- Permissions Policy


---

# 📧 Email Security Intelligence

SentinelX analyzes organization email security posture.

Capabilities:

## MX Intelligence

Detect:

- Mail provider
- Mail servers


Example:

```
Provider:

Google Workspace
```


## SPF Analysis

Detect:

- SPF configuration
- Policy
- Mechanisms


## DMARC Analysis

Detect:

- DMARC policy
- Reporting configuration
- Alignment


## DKIM Discovery

Tests:

- Common selectors
- DKIM availability


## SMTP Mapping

Collect:

- Mail server infrastructure
- Server IP mapping

---

# 🧠 Explainable Risk Engine

SentinelX does not only generate scores.

It explains:

- What is wrong
- Why it matters
- Confidence level
- Security impact


Example:

```json
{
 "risk_score":62,
 "severity":"HIGH",
 "finding":{
   "issue":"DMARC policy monitoring only",
   "severity":"MEDIUM",
   "impact":"EMAIL SECURITY"
 }
}
```

Risk factors:

- SSL security
- Missing headers
- CSP posture
- Email security
- Asset exposure
- Technology risks

---

# 🕸️ Asset Graph Foundation

SentinelX creates relationships between discovered entities.

Current:

```
Organization

     |

 Domain

     |

 Certificate
```


Future:

```
Organization

     |

 Domain

     |

 Subdomain

     |

 IP

     |

 ASN

     |

 Cloud Provider

     |

 Technology

     |

 CVE

     |

 Threat Intelligence
```

---

# 🏗️ Project Architecture

```
SentinelX/

├── collectors/

│   ├── domain_intelligence.py
│   ├── dns_intelligence.py
│   ├── ssl_intelligence.py
│   ├── email_intelligence.py
│   ├── technology_intelligence.py
│   ├── csp_intelligence.py
│   ├── subdomain_intelligence.py
│   ├── risk_engine.py
│   └── asset_graph.py
│

├── reports/

│   └── JSON security reports

│

├── main.py

└── requirements.txt
```

---

# 📊 Example Scan Result

Target:

```
cgu-odisha.ac.in
```

Output:

```
Risk Score:
62

Severity:
HIGH

Subdomains:
12

Assets:
12

Email Provider:
Google Workspace

Scan Time:
76 seconds
```

---

# 🛣️ Roadmap

## Phase 2 — Infrastructure Intelligence 🚧

Goal:

Move from:

```
Asset Exists
```

to:

```
Asset Exposure Intelligence
```


Adding:

```
IP

 |

 ├── ASN

 ├── Cloud Provider

 ├── GeoIP

 ├── Reverse DNS

 ├── CDN Detection

 ├── Open Ports

 ├── Services

 ├── Service Banner

 └── Exposure Score
```

---

## Phase 3 — Vulnerability Intelligence

Planned:

```
Technology

↓

Version

↓

CPE

↓

CVE

↓

CVSS

↓

EPSS

↓

CISA KEV
```

---

## Phase 4 — Threat Intelligence Integration

Planned integrations:

- VirusTotal
- AbuseIPDB
- AlienVault OTX
- GreyNoise
- ThreatFox
- MISP


---

## Phase 5 — Attack Path Discovery

Example:

```
Internet

 ↓

Exposed Asset

 ↓

Technology

 ↓

Vulnerability

 ↓

Exploit

 ↓

Business Impact
```

---

## Phase 6 — AI Security Analyst

Future capabilities:

- Automated security reports
- Risk explanations
- Attack narratives
- Natural language security queries
- Remediation recommendations

---

# 🎯 Research Goals

SentinelX explores research areas including:

- AI-driven Attack Surface Management
- Explainable Security Risk Scoring
- Graph-based Attack Surface Analysis
- Multi-source Asset Correlation
- Continuous External Exposure Monitoring
- LLM-assisted Security Operations

---

# ⚙️ Installation

Clone repository:

```bash
git clone https://github.com/VictorPrasad0026/SentinelX
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run:

```bash
python main.py
```

Enter target domain:

```
example.com
```

---

# ⚠️ Disclaimer

SentinelX is developed for:

- Security research
- Defensive security assessment
- Authorized testing

Only scan systems you own or have explicit permission to test.

---

# 👨‍💻 Author

**Rishabh Prasad**

Cybersecurity Engineer  
Building SentinelX — An AI-Assisted ASM Platform

---

# ⭐ Support

If you find SentinelX interesting:

- Star the repository
- Follow development progress
- Contribute ideas

More capabilities are being actively developed.

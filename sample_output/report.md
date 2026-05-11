# Security Analysis Report

**Generated:** 2026-05-11 15:08:03

---

## 1. Authentication Log Analysis

- **Total failed logins:** 500
- **Total successful logins:** 20
- **Fail/success ratio:** 0.962

### Brute Force IPs

| IP | Failed Attempts |
|-----|----------------|
| 185.220.101.5 | 259 |
| 45.33.32.156 | 202 |
| 10.0.0.1 | 18 |
| 10.0.0.2 | 14 |

### Most Targeted Users

| User | Attempts |
|------|----------|
| root | 131 |
| daniel | 128 |
| admin | 124 |
| ubuntu | 117 |

---

## 2. Web Access Log Analysis

- **Total requests:** 3168
- **Attack patterns detected:** 127

### Top 5 IPs by Request Volume

| IP | Requests |
|----|----------|
| 10.0.0.1 | 1835 |
| 66.249.66.1 | 591 |
| 185.220.101.5 | 294 |
| 45.33.32.156 | 278 |
| 192.168.1.50 | 170 |

### HTTP Status Distribution

| Status Code | Count |
|-------------|-------|
| 200 | 3084 |
| 403 | 42 |
| 500 | 42 |

### Attack Requests Detected

| IP | Method | Path | Status |
|----|--------|------|--------|
| 192.168.1.50 | GET | /admin/../../../etc/passwd | 403 |
| 185.220.101.5 | GET | /wp-admin/ | 500 |
| 10.0.0.1 | GET | /search?q=<script>alert(1)</script> | 500 |
| 66.249.66.1 | GET | /cgi-bin/test.cgi?cmd=id | 200 |
| 10.0.0.1 | GET | /admin/../../../etc/passwd | 500 |
| 10.0.0.1 | GET | /cgi-bin/test.cgi?cmd=id | 200 |
| 66.249.66.1 | GET | /search?q=<script>alert(1)</script> | 403 |
| 66.249.66.1 | GET | /search?q=<script>alert(1)</script> | 500 |
| 66.249.66.1 | GET | /admin/../../../etc/passwd | 403 |
| 10.0.0.1 | GET | /cgi-bin/test.cgi?cmd=id | 200 |
| 10.0.0.1 | GET | /search?q=<script>alert(1)</script> | 403 |
| 10.0.0.1 | GET | /admin/../../../etc/passwd | 500 |
| 10.0.0.1 | GET | /admin/../../../etc/passwd | 500 |
| 185.220.101.5 | GET | /cgi-bin/test.cgi?cmd=id | 500 |
| 10.0.0.1 | GET | /search?q=<script>alert(1)</script> | 200 |
| 66.249.66.1 | GET | /search?q=<script>alert(1)</script> | 403 |
| 185.220.101.5 | GET | /wp-admin/ | 500 |
| 66.249.66.1 | GET | /search?q=<script>alert(1)</script> | 200 |
| 66.249.66.1 | GET | /cgi-bin/test.cgi?cmd=id | 500 |
| 66.249.66.1 | GET | /admin/../../../etc/passwd | 403 |

---

## 3. Anomaly Detection (3-Sigma Rule)

| Hour | Requests | Z-Score | Mean | StDev |
|------|----------|---------|------|-------|
| 11/May/2026-03 | 944 | 4.68σ | 132 | 173.4 |

---

# Reconnaissance Report: duolingo.com

**Type:** domain
**Timestamp:** 2026-05-11T20:31:59.440888Z

## WHOIS Information
- Registrar: Amazon Registrar, Inc.
- Registrant: Identity Protection Service

## DNS Records

### A Records
- 35.153.234.88
- 98.89.254.120
- 54.205.107.150
- 54.167.143.88

### MX Records
- 20 alt2.aspmx.l.google.com.
- 20 alt1.aspmx.l.google.com.
- 30 aspmx5.googlemail.com.
- 30 aspmx4.googlemail.com.
- 30 aspmx2.googlemail.com.
- 10 aspmx.l.google.com.
- 30 aspmx3.googlemail.com.

### NS Records
- ns-1020.awsdns-63.net.
- ns-1117.awsdns-11.org.
- ns-1904.awsdns-46.co.uk.
- ns-247.awsdns-30.com.

### TXT Records
- "klaviyo-site-verification=RKdcF3"
- "amazonses:+SIz2NZPqYri3C+PSIyKShZIbuI4rNpbLlES7lmvpu4="
- "klaviyo-site-verification=TGmZS7"
- "v=spf1 ip4:100.25.59.11 ip4:205.201.128.0/20 ip4:198.2.128.0/18 ip4:148.105.8.0/21 ip4:52.73.203.75 ip4:52.70.130.33 include:amazonses.com include:_spf.google.com include:_spf.salesforce.com include:mail.zendesk.com include:aspmx.pardot.com ~all"
- "google-site-verification=975UaH3lkKONB88HjWDDg34p8cdCqyTVSq_KGBAXrmU"
- "h1-domain-verification=sjPBeaGqQwEe8YhJ3W8JVNJa7WDQFAzc6AHkURoErkh324Yy"
- "_vg2bua41v8x489g1y55hg3hr4h3qmj0"
- "docker-verification=b4ead4c5-fd66-42a5-a684-8f2e7f4c1417"
- "stripe-verification=c8d270a115adc8c5a0a84fb24e17b7d05f66aad648d01e86f15548c6d0254ff5"
- "aliyun-site-verification=1acfc148-50be-45c8-a021-3c933fc8eff9"
- "slack-domain-verification=iuNWYimCCkEpnistAJvWc4YOZF8izoZ23TCDek0I"
- "atlassian-sending-domain-verification=423a5faf-1cfa-4704-a38a-f7adae302dd6"
- "jetbrains-domain-verification=bt8q7duih10l9pmf5fo5yy8wf"
- "rippling-domain-verification=9692f0635321f04d"
- "spacelift-domain-verification=519xtPXm"
- "anthropic-domain-verification-z4335b=YssTBALPY7K784Sri4FjVHjd3"
- "e622flctk14s3cs3ccdauh8uth"
- "openai-domain-verification=dv-A4cFxdrYIEodfG6UiQU0qxnT"
- "pardot_208162_*=c15d5cb1b9f31e26058e1f30bda9e5d65c57cfeea37b34af8e1dd88474460e90"
- "apple-domain-verification=bMPI889zOgALUenN"
- "MS=ms66530579"
- "openai-domain-verification=dv-ieCpefZUqvVQwb8f7o4SlFye"
- "pardot_208162_*=610bfb45f202232a79db94c298b30d14332a62a6894e695b025fa7949d7b03fa"

## HTTP Headers

### HTTP
**Notable Security Headers:**
- Content-Security-Policy: **MISSING**
- Strict-Transport-Security: **MISSING**
- X-Frame-Options: **MISSING**
- X-Content-Type-Options: **MISSING**

### HTTPS
**Notable Security Headers:**
- Content-Security-Policy: **MISSING**
- Strict-Transport-Security: **MISSING**
- X-Frame-Options: **MISSING**
- X-Content-Type-Options: **MISSING**


---

# Reconnaissance Report: 8.8.8.8

**Type:** ip
**Timestamp:** 2026-05-11T20:34:11.302028Z

## nmap Scan Results
| Port | Service |
|------|----------|
| 53 | tcpwrapped |
| 443 | tcpwrapped |

## Reverse DNS

## WHOIS Information

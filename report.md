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
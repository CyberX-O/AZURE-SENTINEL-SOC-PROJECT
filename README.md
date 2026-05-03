# AZURE-SENTINEL-SOC-PROJECT
Secure Azure cloud environment with identity management, network security, SIEM monitoring, and brute force attack detection using Microsoft Sentinel
# 🔐 Secure Azure Cloud Environment with Monitoring & Threat Detection

![Azure](https://img.shields.io/badge/Microsoft_Azure-0078D4?style=for-the-badge&logo=microsoft-azure&logoColor=white)
![Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Defender](https://img.shields.io/badge/Defender_for_Cloud-00B4D8?style=for-the-badge&logo=microsoft&logoColor=white)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)

---

## 📌 Project Overview

This project documents the end-to-end build of a secure cloud environment on **Microsoft Azure**, simulating real-world security operations. As a cloud security analyst, I configured identity and access controls, network segmentation, secure storage, centralised logging, and threat detection — culminating in a **simulated brute force SSH attack** detected and investigated through **Microsoft Sentinel**.

> **Role:** Cloud Security Analyst  
> **Platform:** Microsoft Azure  
> **Approach:** Azure Portal (GUI) + Azure Cloud Shell (SSH & attack simulation only)

---

## 🏗️ Project Architecture

```
User → Azure AD → Virtual Network (VNet)
                        ↓
               Linux Virtual Machine
                        ↓
               Azure Storage Account
                        ↓
     Azure Monitor + Defender for Cloud + Microsoft Sentinel
```

---

## 🛠️ Tools & Services Used

| Tool / Service | Purpose |
|---|---|
| Microsoft Azure (Free Account) | Cloud platform |
| Azure Active Directory (Azure AD) | Identity, RBAC, MFA |
| Azure Virtual Network (VNet) | Network segmentation |
| Network Security Groups (NSG) | Traffic control |
| Azure Storage Account | Secure private storage |
| Azure Monitor | Centralised logging and alerts |
| Microsoft Defender for Cloud | Cloud security posture management |
| Microsoft Sentinel | SIEM – detection, analytics rules, incidents |
| Log Analytics Workspace | Central log store |
| Azure Cloud Shell | SSH connections and attack simulation |
| KQL (Kusto Query Language) | Log querying in Sentinel |

---

## 📋 Step-by-Step Implementation

### Step 1 — Create Azure Free Account & Enable MFA
- Signed up for a Microsoft Azure Free Account
- Navigated to **Azure Active Directory → Security → MFA**
- Enforced MFA for all users in the directory


---

### Step 2 — Configure Identity & Access (Azure AD)
- Created a new standard user account (avoided using Global Admin for daily tasks)
- Created a security group: **SecurityTeam**
- Assigned roles using **RBAC** following the **Principle of Least Privilege**:
  - `Security Reader` – read-only access to Defender for Cloud
  - `Log Analytics Reader` – access to query logs in Sentinel
- Confirmed MFA was required for the new user

---

### Step 3 — Build Secure Network (VNet)
- Created a **Virtual Network (VNet)**
- Added two subnets:
  - **Public Subnet** – for the Linux VM
  - **Private Subnet** – for internal resources
- Configured **Network Security Group (NSG)** inbound rules:

| Rule | Port | Action |
|---|---|---|
| Allow SSH from my IP | 22 (TCP) | Allow |
| Deny all other inbound | Any | Deny |

---

### Step 4 — Deploy and Harden the Linux Virtual Machine
- Created a **Linux VM (Ubuntu)** inside the VNet public subnet
- Secured with **SSH key authentication** (no password login)
- Disabled root login
- Updated system packages after first login

---

### Step 5 — Secure Azure Storage
- Created a **Storage Account** with:
  - Public blob access: **Disabled**
  - Secure transfer required: **Enabled (HTTPS only)**
  - Encryption at rest: **Enabled (default)**
- Tested public access to the blob URL — returned **403 Forbidden** 


---

### Step 6 — Enable Logging & Monitoring (Azure Monitor)
- Created a **Log Analytics Workspace** to centralise all logs
- Enabled **Diagnostic Settings** for:
  - Linux VM → sent metrics and logs to the workspace
  - Storage Account → sent read/write/delete logs to the workspace
- Created **Azure Monitor Alerts** for:
  - Failed login attempts
  - Suspicious activity patterns

---

### Step 7 — Enable Microsoft Defender for Cloud
- Navigated to **Defender for Cloud → Environment Settings**
- Enabled Defender plans:
  - ✅ Defender for Servers
  - ✅ Defender for Storage
  - ✅ Defender for Databases
- Enabled **Azure Security Benchmark** policy under Security Policy
- Reviewed Security Recommendations and Secure Score

---

### Step 8 — Set Up Microsoft Sentinel (SIEM)

#### 8a. Connect Azure Activity Logs
- Navigated to **Sentinel → Data Connectors → Azure Activity**
- Connected via **Diagnostic Settings** (manual method — more reliable than policy):
  - **Subscriptions → Diagnostic Settings → + Add diagnostic setting**
  - Selected: Administrative, Security, Alert, Policy logs
  - Destination: Log Analytics Workspace
- Connected successfully within 15 minutes 


#### 8b. Connect Syslog (AMA Method)
- Created a **Data Collection Rule (DCR)**:
  - Added Linux VM as a resource
  - Facilities: `LOG_AUTH` and `LOG_AUTHPRIV`
  - Log level: `LOG_DEBUG` (captures all failed login detail)
  - Destination: Sentinel Log Analytics Workspace
- Verified **AzureMonitorLinuxAgent** was installed under VM → Extensions
- Restarted the agent from Cloud Shell:

```bash
sudo systemctl restart azuremonitoragent
sudo systemctl restart syslog
```
---

### Step 9 — Simulate a Brute Force Attack

SSH into the Linux VM from Azure Cloud Shell:

```bash
ssh -i /path/to/key.pem azureuser@<Public-IP>
```

Simulated 20 failed SSH login attempts using the `logger` command:

```bash
for i in {1..20}; do logger -p auth.info "Failed password for invaliduser from 192.168.1.1 port 22 ssh2"; done
```

Verified logs were generated on the VM:

```bash
sudo cat /var/log/auth.log | grep "Failed password" | tail -20
```

Confirmed logs appeared in Sentinel using KQL:

```kql
Syslog
| where SyslogMessage contains "Failed password"
| where TimeGenerated > ago(15m)
| take 20
```

---

### Step 10 — Create Analytics Rule in Microsoft Sentinel

Navigated to **Sentinel → Analytics → + Create → Scheduled Query Rule**

| Field | Value |
|---|---|
| Name | SSH Brute Force Detection |
| Severity | High |
| Status | Enabled |
| Tactic | Credential Access |
| Technique | T1110 – Brute Force |
| Sub-techniques | T1110.001 – Password Guessing, T1110.003 – Password Spraying |

**KQL Query:**

```kql
Syslog
| where SyslogMessage contains "Failed password"
| where TimeGenerated > ago(1h)
```

**Scheduling:**
- Run every: `5 minutes`
- Lookup data from last: `1 hour`
- Alert threshold: `Greater than 0`
- Incident Settings: `Create incidents from alerts → On`


---

### Step 11 — Incident Investigation & Response

Located the **SSH Brute Force Detection** incident in **Sentinel → Incidents**.

Ran investigation queries to check for successful logins:

```kql
Syslog
| where SyslogMessage contains "Accepted password"
    or SyslogMessage contains "Accepted publickey"
| where TimeGenerated > ago(24h)
| project TimeGenerated, SyslogMessage, HostIP, Computer
```

**Investigation Findings:**

| Finding | Conclusion |
|---|---|
| Failed password from 192.168.1.1 | Simulated – fake IP hardcoded in logger command |
| Accepted publickey from 172.201.33.160 | Legitimate – analyst SSH from local machine |
| Accepted publickey from Cloud Shell IP | Legitimate – analyst SSH from Azure Cloud Shell |
| No unknown foreign IPs | No unauthorised access detected ✅ |


**Incident Closed:**

| Field | Value |
|---|---|
| Status | Closed |
| Classification | True Positive – Suspicious Activity |
| Comment | Simulated brute force attack. All successful logins confirmed as analyst access from known IPs. No unauthorised access detected. |

---

## ⚠️ Roadblocks & How I Fixed Them

### Azure Activity Connector
| Roadblock | Fix |
|---|---|
| Connector not connecting after 30 mins | Found 4 duplicate policy assignments conflicting — deleted 3, kept 1 |
| Still not connecting after cleanup | Bypassed policy; connected manually via Subscriptions → Diagnostic Settings |

### Syslog Connector
| Roadblock | Fix |
|---|---|
| SSH connection timed out | Port 22 was blocked by NSG — added inbound Allow rule for port 22 |
| Wrong IP address used | Used Private IP instead of Public IP — switched to Public IP from VM Overview |
| Permission denied (publickey) | Was missing the -i flag — used `ssh -i key.pem azureuser@<IP>` |
| Logs not flowing into Sentinel | DCR was missing LOG_AUTH and LOG_AUTHPRIV facilities at LOG_DEBUG level |

### Analytics Rule & Incidents
| Roadblock | Fix |
|---|---|
| No analytics rules found | Created a custom Scheduled Query Rule manually with MITRE ATT&CK mapping |
| Rule showing in red (error) | Query used non-existent field `HostIP` — simplified the KQL query |
| No brute force script on VM | Used the Linux `logger` command to simulate failed logins directly |

---

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique |
|---|---|---|
| Credential Access | T1110 – Brute Force | T1110.001 – Password Guessing |
| Credential Access | T1110 – Brute Force | T1110.003 – Password Spraying |

---

## 💡 Key Lessons Learned

1. **Duplicate Azure Policy assignments conflict** — always check Policy → Assignments before creating a new one
2. **Manual Diagnostic Settings** are more reliable than policy-based connections in a lab environment
3. **LOG_DEBUG** captures more auth detail than LOG_INFO — essential for security monitoring
4. **Analytics Rules are mandatory** in Sentinel — raw logs do not auto-generate incidents
5. **The Linux `logger` command** is a simple, effective way to simulate Syslog events
6. **Always verify the full chain:** VM Logs → Syslog Connector → Sentinel Logs → Analytics Rule → Alert → Incident
7. **IP investigation matters** — the same VM can show multiple legitimate IPs (local machine + Cloud Shell)

---

## ✅ Project Checklist

| Task | Method | Status |
|---|---|---|
| Azure Free Account + MFA | Portal | ✅ |
| Azure AD – Users, Groups, RBAC | Portal | ✅ |
| VNet + Subnets + NSG | Portal | ✅ |
| Linux VM Deployment & Hardening | Portal + Cloud Shell | ✅ |
| Secure Storage Account | Portal | ✅ |
| Azure Monitor + Diagnostic Logs | Portal | ✅ |
| Defender for Cloud – Plans + Benchmark | Portal | ✅ |
| Sentinel – Azure Activity Connector | Portal (Manual Diagnostic) | ✅ |
| Sentinel – Syslog Connector (AMA/DCR) | Portal + Cloud Shell | ✅ |
| Brute Force Simulation | Cloud Shell (logger command) | ✅ |
| Analytics Rule (MITRE T1110) | Portal | ✅ |
| Incident Detection & Investigation | Portal + KQL | ✅ |
| Incident Closure & Documentation | Portal | ✅ |

---

## 📁 Repository Structure

```
azure-sentinel-soc-project/
├── README.md
├── Azure_Sentinel_Project.docx
└── screenshots/
    ├── 01-mfa-enabled.png
    ├── 02-azure-ad-users-groups.png
    ├── 02-rbac-role-assignments.png
    ├── 03-vnet-subnets.png
    ├── 03-nsg-inbound-rules.png
    ├── 04-linux-vm-running.png
    ├── 04-ssh-connection.png
    ├── 05-storage-configuration.png
    ├── 05-storage-public-access-denied.png
    ├── 06-log-analytics-workspace.png
    ├── 06-azure-monitor-alerts.png
    ├── 07-defender-plans.png
    ├── 07-security-recommendations.png
    ├── 08-azure-activity-connected.png
    ├── 08-syslog-connected.png
    ├── 08-ama-agent-installed.png
    ├── 09-brute-force-simulation.png
    ├── 09-sentinel-logs-results.png
    ├── 10-analytics-rule-mitre.png
    ├── 10-rule-logic-scheduling.png
    ├── 11-sentinel-incident.png
    ├── 11-incident-details.png
    ├── 11-successful-login-investigation.png
    └── 11-incident-closed.png
```

---

*Project completed as part of a hands-on Cloud Security Analyst portfolio.*

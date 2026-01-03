# SIEM Log Analysis and Threat Investigation
A Splunk-based cybersecurity investigation project analysing real-world log data to detect and confirm a multi-factor authentication (MFA) bypass attack originating from a foreign IP, demonstrating incident detection, analysis and response skills.

## Objective

The project aimed to investigate a suspected data breach within WidgetCo’s environment using Splunk. The primary goal was to analyse multiple log sources to confirm unauthorised access, identify the attack path and validate a potential multi-factor authentication (MFA) bypass originating from a foreign IP address.

### Skills Learned

- Advanced understanding of SIEM concepts and practical application using Splunk.
- Proficiency in analysing and interpreting logs.
- Ability to generate and recognise attack signatures and patterns.
- Development of critical thinking and problem-solving skills in cybersecurity.
- Visualisation of geolocation anomalies and privileged access.
- Development of detection dashboards for MFA and geo-anomalies.

### Tools Used

- Splunk Enterprise – log ingestion, correlation and visualisation.
- iplocation command – to geolocate IP addresses and confirm anomalies.
- Datasets analysed:
    - MFA.csv
    - VPN.csv
    - Cloud.csv
    - ITAdmin.csv
    - EmployeeData.csv
  
## Steps

### 1. MFA Bypass Detection
Used Splunk to identify a successful MFA bypass originating from IP 180.76.54.93, which accessed both Cloud and IT Admin Portal systems.
```kusto
index=final* source="MFA.csv" "Authentication Method"="Bypass"
| table Date Time "IP Address" Username Application Result
| sort "IP Address", Date, Time
```

<div align="center">
  <img width="1143" height="456" alt="image" src="https://github.com/user-attachments/assets/d74cbb57-69e3-4a50-bc1a-e072adf677e8" />
  <p><em>Fig 1: MFA Bypass Event Logs</em></p>
</div>

### 2. Concurrent Login Detection
Compared user DDDXUB’s sessions in VPN.csv and Cloud.csv to detect impossible travel: simultaneous logins from New York (VPN) and China (Cloud).

```kusto
index=final* source IN ("VPN.csv", "Cloud.csv")
| search Username="DDDXUB"
| table Date Time Username "IP Address" Application Result
| sort Date Time
```
<div align="center">
  <img width="1107" height="421" alt="image" src="https://github.com/user-attachments/assets/8642cd28-def3-42d5-818d-68b9173ccf97" />
  <p><em>Fig 2: Concurrent Login Analysis</em></p>
</div>

### 3. Geolocation Verification
Validated IP origins to distinguish legitimate (US-based) users from the attacker.

```kusto
index=final* source="MFA.csv"
| iplocation "IP Address"
| table "IP Address" City Region Country
| dedup "IP Address"
```
<div align="center">
  <img width="1141" height="505" alt="image" src="https://github.com/user-attachments/assets/c2fe361b-a392-42be-91cd-5f87a17665b1" />
  <p><em>Fig 3: Geolocation Verification Reports</em></p>
</div>

<div align="center">
  <img width="1145" height="115" alt="image" src="https://github.com/user-attachments/assets/4e5b6563-0123-4e27-b27a-3ed70a57733f" />
  <p><em>Fig 4: Geolocation of Other Users</em></p>
</div>

Legitimate employee IPs (192.198.105.143, 70.107.95.217, 98.10.249.169) were from New York, USA, while 180.76.54.93 originated from China, confirming malicious activity.

### 4. Admin Access Confirmation
Linked MFA bypass events with administrative portal access, confirming escalation of privileges post-compromise.

```kusto
index=final* source IN ("MFA.csv", "ITAdmin.csv")
| search "IP Address"="180.76.54.93"
| table Date Time Username Application Result "IP Address"
| sort Date Time
```
<div align="center">
  <img width="1141" height="224" alt="image" src="https://github.com/user-attachments/assets/950b062a-61ac-4d61-93b8-9a2eadb3f211" />
  <p><em>Fig 5: IT Admin Portal Access Records</em></p>
</div>

## Dashboards

### Security Breach Dashboard
Provides a consolidated view of confirmed breach activity, highlighting repeated unauthorised access attempts to critical systems and identifying the primary malicious IP involved in the attack.

### Suspicion Confirmation Dashboard
Validates suspicious behaviour through geolocation analysis, clearly distinguishing legitimate user activity from foreign-based access that confirmed credential compromise.


## Outcome
The Splunk analysis confirmed a successful MFA bypass and privileged access from IP 180.76.54.93 (China) using the stolen credentials of user DDDXUB.
By combining MFA, Cloud, VPN and ITAdmin logs, the investigation proved:

- Unauthorised foreign access to critical systems
- Stolen credentials used across multiple platforms
- Geolocation anomaly confirming malicious origin

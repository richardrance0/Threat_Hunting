<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/richardrance0/Threat_Hunting_Scenarios/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` table for any file with “tor” in it.

The user “theeRick” on DeviceName “WinRichStigInte”downloaded a tor installer that generated tor-related activity and a file called `tor-shopping-list.txt` was downloaded to the desktop. These events began at `2025-05-30T02:07:36.8356006Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "WinRichStigInte"
| where InitiatingProcessAccountName == "theerick"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-05-30T02:07:36.8356006Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, filename = FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="889" alt="tor browser screenshot" src="https://github.com/user-attachments/assets/24e68c46-15e7-40d3-9389-645dfbc3d4bf" />


---

### 2. Searched the `DeviceProcessEvents` table for the process `tor-browser-windows-x86_64-portable-14.5.3.ex`.

On `2025-05-30T02:07:00Z`, a user named "theerick" on the computer "winrichstiginte" initiated the execution of the Tor Browser installer (version 14.5.3) from their Downloads folder. The file, named `tor-browser-windows-x86_64-portable-14.5.3.exe`, has a SHA256 hash of `3b7e78a4ccc935cfe71a0e4d41cc297d48a44e722b4a46f73b5562aed9c1d2ea`, confirming its authenticity as the official release from the Tor Project.

This action indicates that the user was setting up the Tor Browser, a tool designed to enhance online privacy and anonymity by routing internet traffic through a global network of servers. The portable version chosen allows the browser to run without installation, offering flexibility for use across different systems.

Given the legitimate source and the verified hash, this installation appears to be a standard setup of the Tor Browser for privacy-focused browsing.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName contains "WinRichStigInte"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256,
ProcessCommandLine
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/43d8818e-8aea-46dc-a8de-a7ff9a485296)


---

### 3. Searched the `DeviceNetworkEvents` table to find the `RemotePort`(s) that Tor is known to use.

On `2025-05-30T16:56:00Z`, a user account named "theerick" on the device "winrichstiginte" launched tor.exe, initiating a connection to the remote IP `185.246.86.175` over port `9001`—a known port used for Tor network traffic. This activity suggests the Tor Browser was actively used to access the anonymizing network at that time. Other sites were visited as well.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "WinRichStigInte"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/555204d9-4f0d-441a-bac9-0ab307dd9be5)


---

### 4. Searched the `DeviceFileEvents` table for evidence of any file creation.

On the evening of 2025-05-30T02:32:00Z, the user "theeRick" remotely accessed the device "winrichstiginte" via Guacamole RDP from IP `10.0.8.4`, and used Notepad to create a file named `tor-shopping-list.txt` on their desktop. 

The file, only 83 bytes in size, was saved under the path `C:\Users\theeRick\Desktop\`. While the content is unknown, the filename and context suggest a possible preparation or reference for activities related to the Tor network.

**Query used to locate events:**

```kql
DeviceFileEvents
	| where DeviceName contains "WinRichStigInte"
| where FileName contains "shopping-list.txt"

```
![image](https://github.com/user-attachments/assets/6bb4441a-5042-4122-b467-5c218cc02b40)


---

## Chronological Event Timeline 

### 1. Tor Browser Installer Executed

- **Timestamp:** `2025-05-30T02:07:00Z`
- **Event:** The user "theeRick" executed `tor-browser-windows-x86_64-portable-14.5.3.exe` from the Downloads folder on device "winrichstiginte".
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-30T02:32:00Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop using Notepad, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\theeRick\Desktop\tor-shopping-list.txt`

### 3. Network Connection - TOR Network

- **Timestamp:** `2025-05-30T16:56:00Z`
- **Event:** A network connection to IP `185.246.86.175` on port `9001` by user "theeRick" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\theeRick\desktop\tor browser\browser\torbrowser\tor\tor.exe`


---

## Summary

Summary Interpretation
The user downloaded and executed the Tor Browser using a portable version to avoid system-wide installation. Shortly after, they created a plain-text file (likely for planning purposes) during a remote desktop session. The next morning, the browser was actively used to route traffic through the Tor anonymity network, including outbound connections to known Tor ports and IPs.


---

## Response Taken

TOR usage was confirmed on endpoint WinRichStigIntern
. The device was isolated and the user's direct manager was notified.

---

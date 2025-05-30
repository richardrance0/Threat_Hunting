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

### 1. Searched the DeviceFileEvents table for any file with “tor” in it.

The user “theeRick” on DeviceName “WinRichStigInte”downloaded a tor installer that generated tor-related activity and a file called “tor-shopping-list.txt” was downloaded to the desktop. These events began at 2025-05-30T02:07:36.8356006Z.

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

### 2. Searched the DeviceProcessEvents table for the process "tor-browser-windows-x86_64-portable-14.5.3.ex.

On May 29, 2025, at 9:07 PM, a user named "theerick" on the computer "winrichstiginte" initiated the execution of the Tor Browser installer (version 14.5.3) from their Downloads folder. The file, named "tor-browser-windows-x86_64-portable-14.5.3.exe," has a SHA256 hash of 3b7e78a4ccc935cfe71a0e4d41cc297d48a44e722b4a46f73b5562aed9c1d2ea, confirming its authenticity as the official release from the Tor Project .

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

### 3. Searched the DeviceNetworkEvents table to find the RemotePort(s) that Tor is known to use.

On May 30, 2025, at 11:56 AM, a user account named "theerick" on the device "winrichstiginte" launched tor.exe, initiating a connection to the remote IP 185.246.86.175 over port 9001—a known port used for Tor network traffic. This activity suggests the Tor Browser was actively used to access the anonymizing network at that time. Other sites were visited as well.


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

### 4. Searched the DeviceFileEvents table for evidence of any file creation.

On the evening of May 29, 2025, at 9:32 PM, the user "theeRick" remotely accessed the device "winrichstiginte" via Guacamole RDP from IP 10.0.8.4, and used Notepad to create a file named "tor-shopping-list.txt" on their desktop. 

The file, only 83 bytes in size, was saved under the path C:\Users\theeRick\Desktop\. While the content is unknown, the filename and context suggest a possible preparation or reference for activities related to the Tor network.

**Query used to locate events:**

```kql
DeviceFileEvents
	| where DeviceName contains "WinRichStigInte"
| where FileName contains "shopping-list.txt"

```
![image](https://github.com/user-attachments/assets/6bb4441a-5042-4122-b467-5c218cc02b40)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---

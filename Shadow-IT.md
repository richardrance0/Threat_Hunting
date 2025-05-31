# Threat Event (Shadow IT)
**Unauthorized use of remote access software involving proprietary information**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download TeamViewer, AnyDesk, and Dropbox from their official websites.
2. Save the executables in the AppData folder to avoid triggering corporate software installation alerts.
3. Add Dropbox to the Windows Registry for persistence @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Dropbox".
4. To avoid detection, the following is performed:

	a. Enable auto-start in AnyDesk and Dropbox

	b. Minimize visible windows

	c. Occasionally rename files to avoid suspicion
5. Run the executables: TeamViewer.exe, AnyDesk.exe, Dropbox.exe
6. With TeamViewer running, the employee remotey accesses their work computer from their personal machine without going through the company VPN.
7. They browse a private link to the competitor's website.
8. Documents from company ABC are sent to Dropbox, which reaches out to competitor company XYZ.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Logs file-level activity on endpoints, capturing when files are created, modified, deleted, read, or moved — and which processes did it. It’s essential for detecting data exfiltration, unauthorized file access, malware staging, and policy violations like transferring sensitive data to personal cloud folders. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| The DeviceProcessEvents table logs process creation activity on Windows endpoints. It gives visibility into what executables are run, by whom, from where, and how — making it ideal for detecting suspicious behavior like unauthorized software use or file execution.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting outbound connections to cloud-based services like Dropbox. |

---

## Related Queries:
```kql
// Check the DeviceProcessEvents table for remote access tool executables.
DeviceProcessEvents
| where FileName in~ (
    "TeamViewer.exe", "TeamViewer_Service.exe",   	  // TeamViewer
    "AnyDesk.exe",                                 	// AnyDesk
    "Dropbox.exe", "DropboxUpdate.exe"                 // Dropbox
)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc


// Check the DeviceFileEvents table for folder paths to show where remote access tools
// could be installed or executed from.
DeviceFileEvents
| where FolderPath has_any (
    @"TeamViewer",
    @"C:\Program Files (x86)\TeamViewer\",
    @"%AppData%\TeamViewer\",
    @"%AppData%\AnyDesk\",
    @"C:\ProgramData\AnyDesk\",
    @"%AppData%\Dropbox\",
    @"%LocalAppData%\Dropbox\"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ActionType
| order by Timestamp desc


// Check the DeviceProcessEvents table for executable hashes (SHA256) for known
// versions/binaries of remote access tools.
DeviceProcessEvents
| where SHA256 in~ (
    "9f06b5f5c3e44b6c9e50b2a926ba1687eecae00c0ec1f2ec634f2a353b3e5357", // TeamViewer
    "aa05bd20c9cc73346a8e9b0ddf3fbd68bc2e6f5e5e2f8e3f486df48e949e1b67", // AnyDesk
    "e0f71d98c5e2a2e0d9a8a14e2c81441726e9857a54c7986ab8e0b9b49d3a99d4"  // Dropbox
)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc


// Check the DeviceNetworkEvents table for network connections (domains/IPs) that
// connect to TeamViewer, AnyDesk, or Dropbox.
DeviceNetworkEvents
| where RemoteUrl has_any (
    "teamviewer.com",         			 // TeamViewer
    "anydesk.com",            			// AnyDesk
    "dropbox.com",
    "dropboxusercontent.com"  	              // Dropbox
)
or RemoteIP startswith "185.62.190."        // AnyDesk IP block (185.62.190.0/24)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
         RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc


// Check the DeviceRegistryEvents table for persistence artifacts for TeamViewer,
// AnyDesk, or Dropbox.
DeviceRegistryEvents
| where RegistryKey has_any (
    @"HKCU\Software\TeamViewer",
    @"HKLM\SOFTWARE\TeamViewer",
    @"HKCU\Software\AnyDesk",
    @"HKLM\SYSTEM\ControlSet\Services\AnyDesk",
    @"HKCU\Software\Dropbox",
    @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Dropbox"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by Timestamp desc


```

---

## Created By:
- **Author Name**: Richard Rance
- **Author Contact**: https://www.linkedin.com/in/richardrance/
- **Date**: May 30, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `May 30, 2025`  | `Richard Rance`   

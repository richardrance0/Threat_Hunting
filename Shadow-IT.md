Steps attacker would take:

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

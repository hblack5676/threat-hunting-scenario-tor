# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/hblack5676/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "frank-vm" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-05-25T12:23:22.6131735Z`. These events began at `2026-05-25T12:03:18.492909Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "frank-vm"  
| where InitiatingProcessAccountName == "frank-vm"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-05-25T12:03:18.492909Z![Uploading Screenshot 2026-05-25 at 5.58.03 PM.png…]()
)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1397" height="585" alt="Screenshot 2026-05-25 at 5 58 47 PM" src="https://github.com/user-attachments/assets/29a0223d-7e53-4d83-a55d-eb0e33e895f0" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.14.exe". Based on the logs returned, at `2026-05-25T12:08:27.8857912Z`, an employee on the "frank-vm" device ran the file `tor-browser-windows-x86_64-portable-15.0.14.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "frank-vm"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.14.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1397" height="261" alt="Screenshot 2026-05-25 at 6 05 57 PM" src="https://github.com/user-attachments/assets/cc20d50a-ba2a-4fc2-b2fd-a561763a7df5" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "frank-vm" actually opened the TOR browser. There was evidence that they did open it at `2026-05-25T12:09:09.6927674Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "frank-vm"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1397" height="575" alt="Screenshot 2026-05-25 at 6 13 06 PM" src="https://github.com/user-attachments/assets/43855b19-c113-4f4e-86b2-b6423a9000cc" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-05-25T12:11:14.5819763Z`, an employee on the "frank-vm" device successfully established a connection to the remote IP address `80.58.53.213` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\frank-vm\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "frank-vm"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1397" height="575" alt="Screenshot 2026-05-25 at 6 18 26 PM" src="https://github.com/user-attachments/assets/94e19613-c0c1-454d-8c08-bbe176afb35a" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-05-25T12:03:18.492909Z`
- **Event:** The user "frank-vm" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.14.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\frank-vm\Downloads\tor-browser-windows-x86_64-portable-15.0.14.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-05-25T12:08:27.8857912Z`
- **Event:** The user "frank-vm" executed the file `tor-browser-windows-x86_64-portable-15.0.14.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.14.exe /S`
- **File Path:** `C:\Users\frank-vm\Downloads\tor-browser-windows-x86_64-portable-15.0.14.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-05-25T12:09:09.6927674Z`
- **Event:** User "frank-vm" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\frank-vm\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-05-25T12:09:09.6927674Z`
- **Event:** A network connection to IP `80.58.53.213` on port `9001` by user "frank-vm" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\frank-vm\desktop\tor browser\browser\torbrowser\tor\tor.exe`


### 5. File Creation - TOR Shopping List

- **Timestamp:** `2026-05-25T12:23:22.6131735Z`
- **Event:** The user "frank-vm" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\frank-vm\Desktop\tor-shopping-list.txt`

---

## Summary

The user "frank-vm" on the "frank-vm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `frank-vm` by the user `frank-vm`. The device was isolated, and the user's direct manager was notified.

---

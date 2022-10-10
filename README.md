
<div align="center">
 <p>
  <h1>
   Rapidly Search and Hunt through Windows Forensic Artefacts
  </h1>
 </p>
<img style="padding:0;vertical-align:bottom;" height="76" width="300" src="images/chainsaw.png"/>
</div>

---
Chainsaw provides a powerful ‘first-response’ capability to quickly identify threats within Windows forensic artefacts such as Event Logs and MFTs. Chainsaw offers a generic and fast method of searching through event logs for keywords, and by identifying threats using built-in support for Sigma detection rules, and via custom Chainsaw detection rules.

## Features

 - :dart: Hunt for threats using [Sigma](https://github.com/SigmaHQ/sigma) detection rules and custom Chainsaw detection rules
 - :mag: Search and extract forensic artefacts by string matching, and regex patterns
 - :zap: Lightning fast, written in rust, wrapping the [EVTX parser](https://github.com/omerbenamram/evtx) library by [@OBenamram](https://twitter.com/obenamram?lang=en)
 - :feather: Clean and lightweight execution and output formats without unnecessary bloat
 - :fire: Document tagging (detection logic matching) provided by the [TAU Engine](https://github.com/countercept/tau-engine) Library
 - :bookmark_tabs: Output results in a variety of formats, such as ASCII table format, CSV format, and JSON format
 - :computer: Can be run on MacOS, Linux and Windows
---
	  $ ./chainsaw hunt -r rules/ evtx_attack_samples -s sigma/rules --mapping mappings/sigma-event-logs-all.yml --level critical

	   ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
	  ██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
	  ██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
	  ██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
	  ╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
	   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
	      By Countercept (@FranticTyping, @AlexKornitzer)

	  [+] Loading detection rules from: ../../rules/, /tmp/sigma/rules
	  [+] Loaded 129 detection rules (198 not loaded)
	  [+] Loading event logs from: ../../evtx_attack_samples (extensions: .evtx)
	  [+] Loaded 268 EVTX files (37.5 MB)
	  [+] Hunting: [========================================] 268/268

	  [+] Group: Antivirus
	  ┌─────────────────────┬────────────────────┬──────────┬───────────┬─────────────┬────────────────────────────────┬──────────────────────────────────┬────────────────────┐
	  │      timestamp      │     detections     │ Event ID │ Record ID │  Computer   │          Threat Name           │           Threat Path            │        User        │
	  ├─────────────────────┼────────────────────┼──────────┼───────────┼─────────────┼────────────────────────────────┼──────────────────────────────────┼────────────────────┤
	  │ 2019-07-18 20:40:00 │ ‣ Windows Defender │ 1116     │ 37        │ MSEDGEWIN10 │ Trojan:PowerShell/Powersploit. │ file:_C:\AtomicRedTeam\atomic-   │ MSEDGEWIN10\IEUser │
	  │                     │                    │          │           │             │ M                              │ red-team-master\atomics\T1056\   │                    │
	  │                     │                    │          │           │             │                                │ Get-Keystrokes.ps1               │                    │
	  ├─────────────────────┼────────────────────┼──────────┼───────────┼─────────────┼────────────────────────────────┼──────────────────────────────────┼────────────────────┤
	  │ 2019-07-18 20:53:31 │ ‣ Windows Defender │ 1117     │ 106       │ MSEDGEWIN10 │ Trojan:XML/Exeselrun.gen!A     │ file:_C:\AtomicRedTeam\atomic-   │ MSEDGEWIN10\IEUser │
	  │                     │                    │          │           │             │                                │ red-team-master\atomics\T1086\   │                    │
	  │                     │                    │          │           │             │                                │ payloads\test.xsl                │                    │
	  └─────────────────────┴────────────────────┴──────────┴───────────┴─────────────┴────────────────────────────────┴──────────────────────────────────┴────────────────────┘

	  [+] Group: Log Tampering
	  ┌─────────────────────┬───────────────────────────────┬──────────┬───────────┬────────────────────────────────┬───────────────┐
	  │      timestamp      │          detections           │ Event ID │ Record ID │            Computer            │     User      │
	  ├─────────────────────┼───────────────────────────────┼──────────┼───────────┼────────────────────────────────┼───────────────┤
	  │ 2019-01-20 07:00:50 │ ‣ Security Audit Logs Cleared │ 1102     │ 32853     │ WIN-77LTAPHIQ1R.example.corp   │ Administrator │
	  └─────────────────────┴───────────────────────────────┴──────────┴───────────┴────────────────────────────────┴───────────────┘

	  [+] Group: Sigma
	  ┌─────────────────────┬────────────────────────────────┬───────┬────────────────────────────────┬──────────┬───────────┬──────────────────────────┬──────────────────────────────────┐
	  │      timestamp      │           detections           │ count │     Event.System.Provider      │ Event ID │ Record ID │         Computer         │            Event Data            │
	  ├─────────────────────┼────────────────────────────────┼───────┼────────────────────────────────┼──────────┼───────────┼──────────────────────────┼──────────────────────────────────┤
	  │ 2019-04-29 20:59:14 │ ‣ Malicious Named Pipe         │ 1     │ Microsoft-Windows-Sysmon       │ 18       │ 8046      │ IEWIN7                   │ ---                              │
	  │                     │                                │       │                                │          │           │                          │ Image: System                    │
	  │                     │                                │       │                                │          │           │                          │ PipeName: "\\46a676ab7f179e511   │
	  │                     │                                │       │                                │          │           │                          │ e30dd2dc41bd388"                 │
	  │                     │                                │       │                                │          │           │                          │ ProcessGuid: 365ABB72-D9C4-5CC   │
	  │                     │                                │       │                                │          │           │                          │ 7-0000-0010EA030000              │
	  │                     │                                │       │                                │          │           │                          │ ProcessId: 4                     │
	  │                     │                                │       │                                │          │           │                          │ RuleName: ""                     │
	  │                     │                                │       │                                │          │           │                          │ UtcTime: "2019-04-29 20:59:14.   │
	  │                     │                                │       │                                │          │           │                          │ 430"                             │
	  ├─────────────────────┼────────────────────────────────┼───────┼────────────────────────────────┼──────────┼───────────┼──────────────────────────┼──────────────────────────────────┤
	  │ 2019-04-30 20:26:51 │ ‣ CobaltStrike Service         │ 1     │ Microsoft-Windows-Sysmon       │ 13       │ 9806      │ IEWIN7                   │ ---                              │
	  │                     │ Installations in Registry      │       │                                │          │           │                          │ Details: "%%COMSPEC%% /b /c st   │
	  │                     │                                │       │                                │          │           │                          │ art /b /min powershell.exe -no   │
	  │                     │                                │       │                                │          │           │                          │ p -w hidden -noni -c \"if([Int   │
	  │                     │                                │       │                                │          │           │                          │ Ptr]::Size -eq 4){$b='powershe   │
	  │                     │                                │       │                                │          │           │                          │ ll.exe'}else{$b=$env:windir+'\   │
	  │                     │                                │       │                                │          │           │                          │ \syswow64\\WindowsPowerShell\\   │
	  │                     │                                │       │                                │          │           │                          │ v1.0\\powershell.exe'};$s=New-   │
	  │                     │                                │       │                                │          │           │                          │ Object System.Diagnostics.Proc   │
	  │                     │                                │       │                                │          │           │                          │ essStartInfo;$s.FileName=$b;$s   │
	  │                     │                                │       │                                │          │           │                          │ .Arguments='-noni -nop -w hidd   │
	  │                     │                                │       │                                │          │           │                          │ en -c &([scriptblock]::create(   │
	  │                     │                                │       │                                │          │           │                          │ (New-Object IO.StreamReader(Ne   │
	  │                     │                                │       │                                │          │           │                          │ w-Object IO.Compression.GzipSt   │
	  │                     │                                │       │                                │          │           │                          │ ream((New-Object IO.MemoryStre   │
	  │                     │                                │       │                                │          │           │                          │ am(,[Convert]::FromBase64Strin   │
	  │                     │                                │       │                                │          │           │                          │ g(''H4sIAIuvyFwCA7VW+2/aSBD+OZ   │
	  │                     │                                │       │                                │          │           │                          │ H6P1...                          │
	  │                     │                                │       │                                │          │           │                          │ (use --full to show all content) │
	  │                     │                                │       │                                │          │           │                          │ EventType: SetValue              │
	  │                     │                                │       │                                │          │           │                          │ Image: "C:\\Windows\\system32\   │
	  │                     │                                │       │                                │          │           │                          │ \services.exe"                   │
	  │                     │                                │       │                                │          │           │                          │ ProcessGuid: 365ABB72-2586-5CC   │
	  │                     │                                │       │                                │          │           │                          │ 9-0000-0010DC530000              │
	  │                     │                                │       │                                │          │           │                          │ ProcessId: 460                   │
	  │                     │                                │       │                                │          │           │                          │ RuleName: ""                     │
	  │                     │                                │       │                                │          │           │                          │ TargetObject: "HKLM\\System\\C   │
	  │                     │                                │       │                                │          │           │                          │ urrentControlSet\\services\\he   │
	  │                     │                                │       │                                │          │           │                          │ llo\\ImagePath"                  │
	  │                     │                                │       │                                │          │           │                          │ UtcTime: "2019-04-30 20:26:51.   │
	  │                     │                                │       │                                │          │           │                          │ 934"                             │
	  ├─────────────────────┼────────────────────────────────┼───────┼────────────────────────────────┼──────────┼───────────┼──────────────────────────┼──────────────────────────────────┤
	  │ 2019-05-12 12:52:43 │ ‣ Meterpreter or Cobalt        │ 1     │ Service Control Manager        │ 7045     │ 10446     │ IEWIN7                   │ ---                              │
	  │                     │ Strike Getsystem Service       │       │                                │          │           │                          │ AccountName: LocalSystem         │
	  │                     │ Installation                   │       │                                │          │           │                          │ ImagePath: "%COMSPEC% /c ping    │
	  │                     │                                │       │                                │          │           │                          │ -n 1 127.0.0.1 >nul && echo 'W   │
	  │                     │                                │       │                                │          │           │                          │ inPwnage' > \\\\.\\pipe\\WinPw   │
	  │                     │                                │       │                                │          │           │                          │ nagePipe"                        │
	  │                     │                                │       │                                │          │           │                          │ ServiceName: WinPwnage           │
	  │                     │                                │       │                                │          │           │                          │ ServiceType: user mode service   │
	  │                     │                                │       │                                │          │           │                          │ StartType: demand start          │
	  ├─────────────────────┼────────────────────────────────┼───────┼────────────────────────────────┼──────────┼───────────┼──────────────────────────┼──────────────────────────────────┤
	  │ 2019-06-21 07:35:37 │ ‣ Dumpert Process Dumper       │ 1     │ Microsoft-Windows-Sysmon       │ 11       │ 238375    │ alice.insecurebank.local │ ---                              │
	  │                     │                                │       │                                │          │           │                          │ CreationUtcTime: "2019-06-21 0   │
	  │                     │                                │       │                                │          │           │                          │ 6:53:03.227"                     │
	  │                     │                                │       │                                │          │           │                          │ Image: "C:\\Users\\administrat   │
	  │                     │                                │       │                                │          │           │                          │ or\\Desktop\\x64\\Outflank-Dum   │
	  │                     │                                │       │                                │          │           │                          │ pert.exe"                        │
	  │                     │                                │       │                                │          │           │                          │ ProcessGuid: ECAD0485-88C9-5D0   │
	  │                     │                                │       │                                │          │           │                          │ C-0000-0010348C1D00              │
	  │                     │                                │       │                                │          │           │                          │ ProcessId: 3572                  │
	  │                     │                                │       │                                │          │           │                          │ RuleName: ""                     │
	  │                     │                                │       │                                │          │           │                          │ TargetFilename: "C:\\Windows\\   │
	  │                     │                                │       │                                │          │           │                          │ Temp\\dumpert.dmp"               │
	  │                     │                                │       │                                │          │           │                          │ UtcTime: "2019-06-21 07:35:37.   │
	  │                     │                                │       │                                │          │           │                          │ 324"                             │
	  └─────────────────────┴────────────────────────────────┴───────┴────────────────────────────────┴──────────┴───────────┴──────────────────────────┴──────────────────────────────────┘

## Table Of Contents

- [Features](#features)
- [Why Chainsaw?](#why-chainsaw)
- [Quick Start Guide](#quick-start-guide)
  - [Downloading and Running](#downloading-and-running)
  - [EDR and AV Warnings](#edr-and-av-warnings)
  - [What Changed In Chainsaw v2](#what-changed-in-chainsaw-v2)
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
Using the `--sigma` and `--mapping` parameters you can specify a directory containing a subset of SIGMA detection rules (or just the entire SIGMA git repo) and chainsaw will automatically load, convert and run these rules against the provided event logs. The mapping file tells chainsaw which fields in the event logs to use for rule matching. By default, Chainsaw supports a wide range of Event Log types, including but not limited to:

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

See the mapping file for the full list of fields that are used for rule detection, and feel free to extend it to your needs.

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

If you still need an all-in-one package containing the Chainsaw binary, Sigma rules and example Event logs, you can download it from the [releases section](https://github.com/countercept/chainsaw/releases) of this Github repo. In this releases section you will also find pre-compiled binary-only versions of Chainsaw for various platforms and architectures.

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
./chainsaw hunt EVTX-ATTACK-SAMPLES/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```
### EDR and AV Warnings

When downloading and running chainsaw you may find that your local EDR / AntiVirus engine detects Chainsaw as malicious. You can see examples of this in the following Github issues: [Example1](https://github.com/countercept/chainsaw/issues/12), [Example2](https://github.com/countercept/chainsaw/issues/47).

These warnings are typically due to the example event logs and/or Sigma rules which contain references to malicious strings (e.g. "mimikatz"). We have also seen instances where the Chainsaw binary has been detected by a small subset of Anti-Virus engines likely due to some form of heuristics detection.

### What Changed In Chainsaw v2?

In July 2022 we released version 2 of Chainsaw which is a major overhaul of how Chainsaw operates. Chainsaw v2 contains a number of significant improvements, including the following list of highlights:

 - An improved approach to mapping Sigma rules which results in a significant increase in the number of supported Chainsaw rules, and Event Log event types.
 - Improved CLI output which shows a snapshot of all Event Data for event logs containing detections.
 - Support for loading and parsing Event Logs in both JSON and XML format.
 - Cleaner and simpler command line arguments for the Hunt and Search features.
 - Additional optional output information, such as Rule Author, Rule Status, Rule Level etc.
 - The ability to filter loaded rules by status, kind, and severity level.
 - Inbuilt Chainsaw Detection rules have been broken out into dedicated Chainsaw rule files
 - A clean and rewrite of Chainsaw's code to improve readability and to reduce the overhead for community contributions.

If you still wish to use the version 1 of Chainsaw, you can find compiled binaries in the [releases section](https://github.com/countercept/chainsaw/releases), or you can access the source code in the [v1.x.x branch](https://github.com/countercept/chainsaw/tree/v1.x.x). Please note that Chainsaw v1 is no longer being maintained, and all users should look to move to Chainsaw v2.

A massive thank you to  [@AlexKornitzer](https://twitter.com/AlexKornitzer?lang=en) who managed to convert Chainsaw v1's "Christmas Project" codebase into a polished product in v2.

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
	      -o, --output <output>             The path to output results to
	      -e, --regex <pattern>...          A string or regular expression pattern to search for
	      -t, --tau <tau>...                Tau expressions to search with. e.g. 'Event.System.EventID: =4104'
	          --timestamp <timestamp>       The field that contains the timestamp
	          --timezone <timezone>         Output the timestamp using the timezone provided
	          --to <to>                     The timestamp to search up to. Drops any documents newer than the value provided

	  ARGS:
	      <pattern>    A string or regular expression pattern to search for. Not used when -e or -t is specified
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
	      chainsaw hunt [FLAGS] [OPTIONS] [--] [path]...

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
	      -o, --output <output>                A path to output results to
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

    ./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml

   *Hunt through all evtx files using Sigma rules and Chainsaw rules for detection logic and output in CSV format to the results folder*

    ./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv --output results

   *Hunt through all evtx files using Sigma rules for detection logic, only search between specific timestamps, and output the results in JSON format*

     ./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml --from "2019-03-17T19:09:39" --to "2019-03-17T19:09:50" --json

### Acknowledgements
 - [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by [@SBousseaden](https://twitter.com/SBousseaden)
 - [Sigma](https://github.com/SigmaHQ/sigma) detection rules
 - [EVTX parser](https://github.com/omerbenamram/evtx) library by [@OBenamram](https://twitter.com/obenamram?lang=en)
 - [TAU Engine](https://github.com/countercept/tau-engine) Library by [@AlexKornitzer](https://twitter.com/AlexKornitzer?lang=en)

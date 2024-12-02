
<div align="center">
 <p>
  <h1>
   Rapidly Search and Hunt through Windows Forensic Artefacts
  </h1>
 </p>
<img style="padding:0;vertical-align:bottom;" height="76" width="300" src="images/chainsaw.png"/>
</div>

---
Chainsaw provides a powerful ‘first-response’ capability to quickly identify threats within Windows forensic artefacts such as Event Logs and the MFT file. Chainsaw offers a generic and fast method of searching through event logs for keywords, and by identifying threats using built-in support for Sigma detection rules, and via custom Chainsaw detection rules.

## Features

 - :dart: Hunt for threats using [Sigma](https://github.com/SigmaHQ/sigma) detection rules and custom Chainsaw detection rules
 - :mag: Search and extract forensic artefacts by string matching, and regex patterns
 - :date: Create execution timelines by analysing Shimcache artefacts and enriching them with Amcache data
 - :bulb: Analyse the SRUM database and provide insights about it
 - :arrow_down: Dump the raw content of forensic artefacts (MFT, registry hives, ESE databases)
 - :zap: Lightning fast, written in rust, wrapping the [EVTX parser](https://github.com/omerbenamram/evtx) library by [@OBenamram](https://twitter.com/obenamram?lang=en)
 - :feather: Clean and lightweight execution and output formats without unnecessary bloat
 - :fire: Document tagging (detection logic matching) provided by the [TAU Engine](https://github.com/WithSecureLabs/tau-engine) Library
 - :bookmark_tabs: Output results in a variety of formats, such as ASCII table format, CSV format, and JSON format
 - :computer: Can be run on MacOS, Linux and Windows
---

## Table Of Contents

- [Features](#features)
- [Why Chainsaw?](#why-chainsaw)
- [Hunting Logic for Windows Event Logs](#hunting-logic-for-windows-event-logs)
- [Quick Start Guide](#quick-start-guide)
  - [Downloading and Running](#downloading-and-running)
  - [Install/Build with Nix](#installbuild-with-nix)
  - [EDR and AV Warnings](#edr-and-av-warnings)
  - [What changed in Chainsaw v2](#what-changed-in-chainsaw-v2)
- [Examples](#examples)
  - [Searching](#searching)
  - [Hunting](#hunting)
  - [Analysis](#analysis)
    - [Shimcache](#shimcache)
    - [SRUM (System Resource Usage Monitor)](#srum-system-resource-usage-monitor)
  - [Dumping](#srum)
- [Acknowledgements](#acknowledgements)

Extended information can be found in the Wiki for this tool: https://github.com/WithSecureLabs/chainsaw/wiki

## Why Chainsaw?

At WithSecure Countercept, we ingest a wide range of telemetry sources from endpoints via our EDR agent to provide our managed detection and response service. However, there are circumstances where we need to quickly analyse forensic artefacts that hasn’t been captured by our EDR, a common example being incident response investigations on an estate where our EDR wasn’t installed at the time of the compromise. Chainsaw was created to provide our threat hunters and incident response consultants with a tool to perform rapid triage of forensic artefacts in these circumstances.

### Windows Event Logs

Windows event logs provide a rich source of forensic information for threat hunting and incident response investigations. Unfortunately, processing and searching through event logs can be a slow and time-consuming process, and in most cases requires the overhead of surrounding infrastructure – such as an ELK stack or Splunk instance – to hunt efficiently through the log data and apply detection logic. This overhead often means that blue teams are unable to quickly triage Windows event logs to provide the direction and conclusions required to progress their investigations. Chainsaw solves the issue since it allows the rapid search and hunt through Windows event logs.

At the time of writing, there are very few open-source, standalone tools that provide a simple and fast method of triaging Windows event logs, identifying interesting elements within the logs and applying a detection logic rule format (such as Sigma) to detect signs of malicious activity. In our testing, the tools that did exist struggled to efficiently apply detection logic to large volumes of event logs making them unsuitable for scenarios where quick triage is required.

## Hunting Logic for Windows Event Logs

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
 2. Detect key event logs being cleared, or the event log service being stopped
 3. Users being created or added to sensitive user groups
 4. Remote Logins (Service, RDP, Network etc.) events. This helps hunters to identify sources of lateral movement
 5. Brute-force of local user accounts


## Quick Start Guide
### Downloading and Running

With the release of Chainsaw v2, we decided to no longer include the Sigma Rules and EVTX-Attack-Samples repositories as Chainsaw submodules. We recommend that you clone these repositories separately to ensure you have the latest versions.

If you still need an all-in-one package containing the Chainsaw binary, Sigma rules and example Event logs, you can download it from the [releases section](https://github.com/WithSecureLabs/chainsaw/releases) of this GitHub repo. In this releases section you will also find pre-compiled binary-only versions of Chainsaw for various platforms and architectures.

If you want to compile Chainsaw yourself, you can clone the Chainsaw repo:

 `git clone https://github.com/WithSecureLabs/chainsaw.git`

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

### Install/build with Nix

```
├───devShells
│   └───x86_64-linux
│       └───default: development environment 'nix-shell'
├───formatter
│   └───x86_64-linux: package 'alejandra-3.1.0'
└───packages
    └───x86_64-linux
        ├───chainsaw: package 'chainsaw-2.10.1'
        └───default: package 'chainsaw-2.10.1'
```

Chainsaw, as a package, is available via [nixpkgs](https://search.nixos.org/packages?query=chainsaw).
If you're using NixOS, just add `chainsaw` to your system configuration file.

However, if you're not using NixOS, you can still install Chainsaw via Nix. The recommend way is via `nix-shell`, which will temporarily modify your $PATH environment variable.
To do so, please run the following:
```
nix-shell -p chainsaw
```

You can also utilize the fact, that this repo is a flake, and you can run the following:
```
nix profile install github:WithSecureLabs/chainsaw
```

However, if you want to build chainsaw yourself, using Nix, you can once again utilize `flake.nix`, which is provided with this repository. 
To build the binary, please run the following, in the root dir of cloned repo
```
nix build .#
```
This will create `./result` directory, with chainsaw binary located under `./result/bin/chainsaw`. 

### EDR and AV Warnings

When downloading and running chainsaw you may find that your local EDR / AntiVirus engine detects Chainsaw as malicious. You can see examples of this in the following GitHub issues: [Example1](https://github.com/WithSecureLabs/chainsaw/issues/12), [Example2](https://github.com/WithSecureLabs/chainsaw/issues/47).

These warnings are typically due to the example event logs and/or Sigma rules which contain references to malicious strings (e.g. "mimikatz"). We have also seen instances where the Chainsaw binary has been detected by a small subset of Anti-Virus engines likely due to some form of heuristics detection.

### What changed in Chainsaw v2?

In July 2022 we released version 2 of Chainsaw which is a major overhaul of how Chainsaw operates. Chainsaw v2 contains several significant improvements, including the following list of highlights:

 - An improved approach to mapping Sigma rules which results in a significant increase in the number of supported Chainsaw rules, and Event Log event types.
 - Improved CLI output which shows a snapshot of all Event Data for event logs containing detections.
 - Support for loading and parsing Event Logs in both JSON and XML format.
 - Cleaner and simpler command line arguments for the Hunt and Search features.
 - Additional optional output information, such as Rule Author, Rule Status, Rule Level etc.
 - The ability to filter loaded rules by status, kind, and severity level.
 - Inbuilt Chainsaw Detection rules have been broken out into dedicated Chainsaw rule files
 - A clean and rewrite of Chainsaw's code to improve readability and to reduce the overhead for community contributions.

If you still wish to use the version 1 of Chainsaw, you can find compiled binaries in the [releases section](https://github.com/WithSecureLabs/chainsaw/releases), or you can access the source code in the [v1.x.x branch](https://github.com/WithSecureLabs/chainsaw/tree/v1.x.x). Please note that Chainsaw v1 is no longer being maintained, and all users should look to move to Chainsaw v2.

A massive thank you to [@AlexKornitzer](https://twitter.com/AlexKornitzer?lang=en) who managed to convert Chainsaw v1's "Christmas Project" codebase into a polished product in v2.

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
          -q                    Suppress informational output
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
          -q                    Suppress informational output
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

#### Output

    $ ./chainsaw hunt -r rules/ evtx_attack_samples -s sigma/rules --mapping mappings/sigma-event-logs-all.yml --level critical

         ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
        ██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
        ██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
        ██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
        ╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
         ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
            By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

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

### Analysing
#### Shimcache
    COMMAND:
        analyse shimcache                 Create an execution timeline from the shimcache with optional amcache enrichments

    USAGE:
        chainsaw analyse shimcache [OPTIONS] <SHIMCACHE>

    ARGUMENTS:
        <SHIMCACHE>                       The path to the shimcache artefact (SYSTEM registry file)

    OPTIONS:
        -e, --regex <pattern>             A string or regular expression for detecting shimcache entries whose timestamp matches their insertion time
        -r, --regexfile <REGEX_FILE>      The path to a newline delimited file containing regex patterns for detecting shimcache entries whose timestamp matches their insertion time
        -o, --output <OUTPUT>             The path to output the result csv file
        -a, --amcache <AMCACHE>           The path to the amcache artefact (Amcache.hve) for timeline enrichment
        -p, --tspair                      Enable near timestamp pair detection between shimcache and amcache for finding additional insertion timestamps for shimcache entries
        -h, --help                        Print help

- Example pattern file for the  `--regexfile` parameter is included in [analysis/shimcache_patterns.txt](analysis/shimcache_patterns.txt).
- Regex patterns are matched on paths in shimcache entries **converted to lowercase**.

##### Command Examples
   *Analyse a shimcache artefact with the provided regex patterns, and use amcache enrichment with timestamp near pair detection enabled. Output to a csv file.*

    ./chainsaw analyse shimcache ./SYSTEM --regexfile ./analysis/shimcache_patterns.txt --amcache ./Amcache.hve --tspair --output ./output.csv


   *Analyse a shimcache artefact with the provided regex patterns (without amcache enrichment). Output to the terminal.*

    ./chainsaw analyse shimcache ./SYSTEM --regexfile ./analysis/shimcache_patterns.txt

#### SRUM (System Resource Usage Monitor)
The SRUM database parser implemented in Chainsaw differs from other parsers because it does not rely on hardcoded values about the tables. The information is extracted directly from the SOFTWARE hive, which is a mandatory argument. The goal is to avoid errors related to unknown tables.

    COMMAND:
        analyse srum                             Analyse the SRUM database

    USAGE:
        chainsaw analyse srum [OPTIONS] --software <SOFTWARE_HIVE_PATH> <SRUM_PATH>

    ARGUMENTS:
        <SRUM_PATH>                              The path to the SRUM database

    OPTIONS:
        -s, --software <SOFTWARE_HIVE_PATH>      The path to the SOFTWARE hive
            --stats-only                         Only output details about the SRUM database
        -q                                       Suppress informational output
        -o, --output <OUTPUT>                    Save the output to a file
        -h, --help                               Print help

##### Command Example

   *Analyse the SRUM database (the SOFTWARE hive is mandatory)*

    ./chainsaw analyse srum --software ./SOFTWARE ./SRUDB.dat --output ./output.json

##### Output

    $ ./chainsaw analyse srum --software ./SOFTWARE ./SRUDB.dat -o ./output.json

         ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
        ██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
        ██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
        ██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
        ╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
         ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
            By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

        [+] ESE database file loaded from "/home/user/Documents/SRUDB.dat"
        [+] Parsing the ESE database...
        [+] SOFTWARE hive loaded from "/home/user/Documents/SOFTWARE"
        [+] Parsing the SOFTWARE registry hive...
        [+] Analysing the SRUM database...
        [+] Details about the tables related to the SRUM extensions:
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        | Table GUID                               | Table Name                                 | DLL Path                             | Timeframe of the data   | Expected Retention Time |
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        | {5C8CF1C7-7257-4F13-B223-970EF5939312}   | App Timeline Provider                      | %SystemRoot%\System32\eeprov.dll     | 2022-03-10 16:34:59 UTC | 7 days                  |
        |                                          |                                            |                                      | 2022-03-10 21:10:00 UTC |                         |
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        | {B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}   | Tagged Energy Provider                     | %SystemRoot%\System32\eeprov.dll     | No records              | 3 days                  |
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        | {D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}   | WPN SRUM Provider                          | %SystemRoot%\System32\wpnsruprov.dll | 2022-03-10 20:09:00 UTC | 60 days                 |
        |                                          |                                            |                                      | 2022-03-10 21:09:00 UTC |                         |
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        | {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}   | Application Resource Usage Provider        | %SystemRoot%\System32\appsruprov.dll | 2022-03-10 16:34:59 UTC | 60 days                 |
        |                                          |                                            |                                      | 2022-03-10 21:10:00 UTC |                         |
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        | {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}   | Energy Usage Provider                      | %SystemRoot%\System32\energyprov.dll | No records              | 60 days                 |
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        | {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT | Energy Usage Provider (Long Term)          | %SystemRoot%\System32\energyprov.dll | No records              | 1820 days               |
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        | {973F5D5C-1D90-4944-BE8E-24B94231A174}   | Windows Network Data Usage Monitor         | %SystemRoot%\System32\nduprov.dll    | 2022-03-10 16:34:59 UTC | 60 days                 |
        |                                          |                                            |                                      | 2022-03-10 21:10:00 UTC |                         |
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        | {7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}   | vfuprov                                    | %SystemRoot%\System32\vfuprov.dll    | 2022-03-10 20:09:00 UTC | 60 days                 |
        |                                          |                                            |                                      | 2022-03-10 21:10:00 UTC |                         |
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        | {DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}   | Energy Estimation Provider                 | %SystemRoot%\System32\eeprov.dll     | No records              | 7 days                  |
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        | {DD6636C4-8929-4683-974E-22C046A43763}   | Windows Network Connectivity Usage Monitor | %SystemRoot%\System32\ncuprov.dll    | 2022-03-10 16:34:59 UTC | 60 days                 |
        |                                          |                                            |                                      | 2022-03-10 21:10:00 UTC |                         |
        +------------------------------------------+--------------------------------------------+--------------------------------------+-------------------------+-------------------------+
        [+] SRUM database parsed successfully
        [+] Saving output to "/home/user/Documents/output.json"
        [+] Saved output to "/home/user/Documents/output.json"

##### Forensic insights
Information about the new forensic insights related to this artefact can be found in the wiki: https://github.com/WithSecureLabs/chainsaw/wiki/SRUM-Analysis.


### Dumping

    USAGE:
        chainsaw dump [OPTIONS] <PATH>

    ARGUMENTS:
        <PATH>                  The path to an artefact to dump

    OPTIONS:
        -j, --json              Dump in json format
            --jsonl             Print the output in jsonl format
            --load-unknown      Allow chainsaw to try and load files it cannot identify
        -o, --output <OUTPUT>   A path to output results to
        -q                      Suppress informational output
            --skip-errors       Continue to hunt when an error is encountered
        -h, --help              Print help

#### Command Example

   *Dump the SOFTWARE hive*

    ./chainsaw dump ./SOFTWARE.hve --json --output ./output.json


## Acknowledgements
 - [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by [@SBousseaden](https://twitter.com/SBousseaden)
 - [Sigma](https://github.com/SigmaHQ/sigma) detection rules
 - [EVTX parser](https://github.com/omerbenamram/evtx) library by [@OBenamram](https://twitter.com/obenamram?lang=en)
 - [TAU Engine](https://github.com/WithSecureLabs/tau-engine) Library by [@AlexKornitzer](https://twitter.com/AlexKornitzer?lang=en)
 - Shimcache analysis feature developed as a part of [CC-Driver](https://www.ccdriver-h2020.com/) project, funded by the European Union’s Horizon 2020 Research and Innovation Programme under Grant Agreement No. 883543
 - [DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum) by Andrew Rathbun ([@bunsofwrath12](https://twitter.com/bunsofwrath12))
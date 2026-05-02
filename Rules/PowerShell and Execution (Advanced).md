<H1>POWER SHELL & EXECUTION (ADVANCED)</H1>

### PowerShell & Execution

```
</> AAT&CK: T1059.001, T1027 - yaml
title: Suspicious PowerShell Encoded Command Execution
id: 14r92d-ps-encodedcommand-002
status: experimental
description: Detectejecuciónnsospechosa de PowerShell usando comandos codificados junto con patrones asociados con malware, movimineto lateral o evasión de defensa.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/
author: ERR
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.command_and_scripting_interpreter
  - attack.t1059.001
  - attack.obfuscated_files_or_information
  - attack.t1027
logsource:
  product: windows
  category: process_creation
detection:
  selection_process:
    Image|endswith:
      - \powershell.exe
      - \pwsh.exe
  selection_encoded:
    CommandLine|contains:
      - -enc
      - -EncodedCommand
      - /enc
      - /EncodedCommand
  selection_suspicious_flags:
    CommandLine|contains:
      - -nop
      - -w hidden
      - hidden
      - bypass
      - FromBase64String
      - IEX
      - Invoke-Expression
  suspicious_parents:
    ParentImage|endswith:
      - \winword.exe
      - \excel.exe
      - \outlook.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
      - \rundll32.exe
      - \regsvr32.exe
  filter_legitimate_tools:
    ParentImage|contains:
      - \Microsoft Configuration Manager\
      - \SCCM\
      - \IntuneManagementExtension\
      - \PDQ Deploy\
  filter_service_accounts:
    User|contains:
      - SYSTEM
      - svc_backup
  condition: selection_process
    and selection_encoded
    and (selection_suspicious_flags or suspicious_parents)
    and not filter_legitimate_tools
    and not filter_service_accounts
falsepositives:
  - Software deployment tools
  - RMM solutions
  - SCCM / Intune administrative scripts
  - Internal automation using encoded PowerShell
level: high
```

```
</> AAT&CK: T1105 - yaml - 
title: Suspicious PowerShell DownloadString with Execution
id: 14r92d-ps-downloadstring-001
status: experimental
description: Detecta uso sospechoso de DownloadString en PowerShell combinado con la ejecución de patrones comunmente asociados con entrega de malware y/o ataques fileless.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1105/
author: ERR
tags:
  - attack.execution
  - attack.command_and_scripting_interpreter
  - attack.t1059.001
  - attack.ingress_tool_transfer
  - attack.t1105
logsource:
  product: windows
  category: process_creation
detection:
  selection_download:
    CommandLine|contains:
      - DownloadString
      - Net.WebClient
  selection_execution:
    CommandLine|contains:
      - IEX
      - Invoke-Expression
      - iex(
      - iex 
      - Hidden
      - -enc
      - -nop
      - bypass
  selection_process:
    Image|endswith:
      - \powershell.exe
      - \pwsh.exe
  filter_legitimate_paths:
    ParentImage|contains:
      - \Microsoft Configuration Manager\
      - \SCCM\
      - \IntuneManagementExtension\
  condition: all of selection_* and not filter_legitimate_paths
falsepositives:
  - Administrative scripts using PowerShell for software deployment
  - Endpoint management tools (SCCM, Intune, RMM)
  - Legitimate automation using remote script retrieval
level: high
``` 

```
</> AAT&CK: T1105 - yaml
title: PowerShell Invoke-WebRequest
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "Invoke-WebRequest"
  condition: selection
```

```
</> AAT&CK: T1204 - yaml
title: PowerShell from Office
logsource: {product: windows}
detection:
  selection:
    ParentImage|endswith:
      - winword.exe
      - excel.exe
    Image|endswith: powershell.exe
  condition: selection
```

```
</> AAT&CK: T1059.001 - yaml
title: PowerShell IEX Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "IEX"
  condition: selection
```

```
</> AAT&CK: T1564 - yaml
title: PowerShell Hidden Window
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains:
      - "-nop"
      - "-w hidden"
  condition: selection
```

```
</> AAT&CK: T1027 - yaml
title: PowerShell Base64 Long String
logsource: {product: windows}
detection:
  selection:
    CommandLine|re: "[A-Za-z0-9+/]{200,}"
  condition: selection
```

```
</> AAT&CK: T1059.003 - yaml
title: Suspicious Cmd Execution
logsource: {product: windows}
detection:
  selection:
    Image|endswith: cmd.exe
    CommandLine|contains: "/c"
  condition: selection
```

```
</> AAT&CK: T1218.011 - yaml
title: Rundll32 Remote Execution
logsource: {product: windows}
detection:
  selection:
    Image|endswith: rundll32.exe
    CommandLine|contains: "http"
  condition: selection
```

```
</> AAT&CK: T1218.010 - yaml
title: Regsvr32 Remote Script
logsource: {product: windows}
detection:
  selection:
    Image|endswith: regsvr32.exe
    CommandLine|contains: "http"
  condition: selection
```


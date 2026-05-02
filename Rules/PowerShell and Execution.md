<H1>POWER SHELL 6 EXECUTION</H1>

### PowerShell & Execution

```
</> AAT&CK: T1059.001, T1027 - yaml
title: Suspicious PowerShell Encoded Command Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "EncodedCommand"
  condition: selection
```

```
</> AAT&CK: T1105 - yaml - 
title: Suspicious PowerShell DownloadString with Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "DownloadString"
  condition: selection
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


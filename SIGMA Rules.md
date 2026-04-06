<H1> SIGMA RULES </H1>
Las reglas SIGMA son como plantillas genéricas para detectar actividad sospechosa en logs.

:triangular_flag_on_post: Piensa en ellas como: “Si pasa esto en los logs → puede ser un ataque”

No están ligadas a una herramienta concreta. Luego se convierten a formatos específicos (Splunk, Elastic, Sentinel, etc.).

Ejemplo sencillo (fichero YAML)

```
title: Uso sospechoso de PowerShell
detection:
  selection:
    Image: powershell.exe
    CommandLine: "*DownloadString*"
  condition: selection
```

Traducción: Si alguien usa PowerShell para descargar cosas → sospechoso

A continuación tienes un set de ***50 reglas Sigma*** (simplificadas pero funcionales) listas para usar como base.

⚠️ Importante: Están optimizadas para claridad y uso práctico, no para cubrir todos los edge cases.

Deberás adaptar:
- logsource
- campos (Sysmon vs Security vs MDE)
Úsalas como plantilla operativa, no como copy/paste ciego.

## 50 reglas sigma

Ejemplos de reglas para los siguientes topics

- Power Shell Execution [:clipboard:](#PowerShell / Execution)
- Persistence [:anchor:](#Persistence)
- Privilege Escalation & Credential Access [:ticket:](#Privilege Escalation & Credential Access)
- Lateral Movement & Discovery [:ladder:](#Lateral Movement & Discovery)
- Exfiltration & Impact [:goal_net:](#Exfiltration)



### PowerShell / Execution

```
</> yaml
title: Suspicious PowerShell Encoded Command
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "EncodedCommand"
  condition: selection
```

```
</> yaml
title: PowerShell DownloadString
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "DownloadString"
  condition: selection
```

```
</> yaml
title: PowerShell Invoke-WebRequest
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "Invoke-WebRequest"
  condition: selection
```

```
</> yaml
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
</> yaml
title: PowerShell IEX Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "IEX"
  condition: selection
```

```
</> yaml
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
</> yaml
title: PowerShell Base64 Long String
logsource: {product: windows}
detection:
  selection:
    CommandLine|re: "[A-Za-z0-9+/]{200,}"
  condition: selection
```

```
</> yaml
title: Suspicious Cmd Execution
logsource: {product: windows}
detection:
  selection:
    Image|endswith: cmd.exe
    CommandLine|contains: "/c"
  condition: selection
```

```
</> yaml
title: Rundll32 Remote Execution
logsource: {product: windows}
detection:
  selection:
    Image|endswith: rundll32.exe
    CommandLine|contains: "http"
  condition: selection
```

```
</> yaml
title: Regsvr32 Remote Script
logsource: {product: windows}
detection:
  selection:
    Image|endswith: regsvr32.exe
    CommandLine|contains: "http"
  condition: selection
```

### Persistence

```
</> yamltitle: Scheduled Task Creation
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "schtasks /create"
  condition: selection
```

```
</> yaml
title: Registry Run Key Persistence
logsource: {product: windows}
detection:
  selection:
    TargetObject|contains: "CurrentVersion\\Run"
  condition: selection
```

```
</> yaml
title: New Service Installed
logsource: {product: windows}
detection:
  selection:
    EventID: 7045
  condition: selection
```

```
</> yaml
title: Suspicious Service Path
logsource: {product: windows}
detection:
  selection:
    ImagePath|contains: "AppData"
  condition: selection
```

```
</> yaml
title: WMI Persistence
logsource: {product: windows}
detection:
  selection:
    EventID: 5861
  condition: selection
```

```
</> yaml
title: Startup Folder Modification
logsource: {product: windows}
detection:
  selection:
    TargetFilename|contains: "Startup"
  condition: selection
```

```
</> yaml
title: DLL in Temp Execution
logsource: {product: windows}
detection:
  selection:
    Image|contains: ".dll"
    CommandLine|contains: "Temp"
  condition: selection
```

```
</> yaml
title: Autorun Registry Modification
logsource: {product: windows}
detection:
  selection:
    TargetObject|contains: "RunOnce"
  condition: selection
```

```
</> yaml
title: Service Modification
logsource: {product: windows}
detection:
  selection:
    EventID: 7040
  condition: selection
```

```
</> yaml
title: Suspicious Scheduled Task Path
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "AppData"
  condition: selection
```

### Privilege Escalation & Credential Access

```
</> yaml
title: User Added to Administrators
logsource: {product: windows}
detection:
  selection:
    EventID: 4728
  condition: selection
```

```
</> yaml
title: Special Privileges Assigned
logsource: {product: windows}
detection:
  selection:
    EventID: 4672
  condition: selection
```

```
</> yaml
title: RunAs Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "runas"
  condition: selection
```

```
</> yaml
title: LSASS Access
logsource: {product: windows}
detection:
  selection:
    TargetImage|endswith: lsass.exe
  condition: selection
```

```
</> yaml
title: Credential Dump via Procdump
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "procdump"
  condition: selection
```

```
</> yaml
title: Mimikatz Indicators
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains:
      - mimikatz
      - sekurlsa
  condition: selection
```

```
</> yaml
title: SAM Hive Access
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "SAM"
  condition: selection
```

```
</> yaml
title: LSASS Memory Dump
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "lsass"
  condition: selection
```

```
</> yaml
title: Suspicious Token Manipulation
logsource: {product: windows}
detection:
  selection:
    EventID: 4673
  condition: selection
```

```
</> yaml
title: Privileged Group Enumeration
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "net group"
  condition: selection
```

### Lateral Movement & Discovery

```
</> yaml
title: Network Logon
logsource: {product: windows}
detection:
  selection:
    EventID: 4624
    LogonType: 3
  condition: selection
```

```
</> yaml
title: PsExec Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "psexec"
  condition: selection
```

```
</> yaml
title: WMI Remote Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "wmic"
  condition: selection
title: WinRM Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "winrm"
  condition: selection
```

```
</> yaml
title: RDP Logon
logsource: {product: windows}
detection:
  selection:
    EventID: 4624
    LogonType: 10
  condition: selection

```
</> yaml
title: Whoami Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "whoami"
  condition: selection
```

```
</> yaml
title: Netstat Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "netstat"
  condition: selection

```
</> yaml
title: IPConfig Execution
logsource: {product: windows}
detection:
  selection
    CommandLine|contains: "ipconfig"
  condition: selection
```

```
</> yaml
title: NLTest Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "nltest"
  condition: selection
```

```
</> yaml
title: Share Enumeration
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "net share"
  condition: selection
```

### Exfiltration & Impact

```
</> yaml
title: Archive Creation
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains:
      - ".zip"
      - ".rar"
      - ".7z"
  condition: selection
```

```
</> yaml
title: 7zip Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "7z"
  condition: selection
```

```
</> yaml
title: Large File Collection
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "copy"
  condition: selection

```
</> yaml
title: External Network Connection
logsource: {product: windows}
detection:
  selection:
    DestinationIp|notstartswith: "192.168."
  condition: selection
```

```
</> yaml
title: PowerShell Upload
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "Upload"
  condition: selection
```

```
</> yaml
title: Delete Shadow Copies
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "vssadmin delete shadows"
  condition: selection
```

```
</> yaml
title: Delete Backup Catalog
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "wbadmin delete"
  condition: selection
```

```
</> yaml
title: Service Stop
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "net stop"
  condition: selection
```

```
</> yaml
title: Mass File Rename
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "rename"
  condition: selection
```

```
</> yaml
title: Suspicious File Extension Change
logsource: {product: windows}
detection:
  selection:
    TargetFilename|contains: ".locked"
  condition: selection
  ```

<H1>EXFILTRATION & IMPACT</H1> 

### Exfiltration & Impact

```
</> ATT&CK:  - yaml
title: Suspicious Archive Creation for Potential Exfiltration
logsource:
  product: windows
detection:
  selection_cmd:
    CommandLine|contains:
      - ".zip"
      - ".rar"
      - ".7z"
  selection_tools:
    Image|endswith:
      - "\7z.exe"
      - "\7za.exe"
      - "\rar.exe"
      - "\winrar.exe"
      - "\powershell.exe"
  selection_ps:
    CommandLine|contains:
      - "Compress-Archive"
  condition: (selection_cmd and selection_tools) or selection_ps
falsepositives:
  - Actividad legítima de usuarios creando archivos comprimidos
  - Scripts administrativos o backups automatizados
level: medium
description: >
  Detecta la creación de archivos comprimidos (ZIP, RAR, 7Z) mediante herramientas comunes o PowerShell.
  Esta actividad puede estar relacionada con la recopilación y preparación de datos para su exfiltración,
  especialmente si se realiza desde rutas sensibles o fuera de procesos habituales.
  Técnicas MITRE ATT&CK: T1560 (Archive Collected Data), T1041 (Exfiltration Over C2 Channel)

```

```
</> ATT&CK:  - yaml
title: 7zip Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "7z"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Large File Collection
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "copy"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: External Network Connection
logsource: {product: windows}
detection:
  selection:
    DestinationIp|notstartswith: "192.168."
  condition: selection
```

```
</> ATT&CK:  - yaml
title: PowerShell Upload
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "Upload"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Delete Shadow Copies
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "vssadmin delete shadows"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Delete Backup Catalog
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "wbadmin delete"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Service Stop
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "net stop"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Mass File Rename
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "rename"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Suspicious File Extension Change
logsource: {product: windows}
detection:
  selection:
    TargetFilename|contains: ".locked"
  condition: selection
```

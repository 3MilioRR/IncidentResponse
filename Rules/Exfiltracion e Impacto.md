<H1>EXFILTRATION & IMPACT</H1> 

### Exfiltration & Impact


1️⃣    
</> Detecta la creación de archivos comprimidos (ZIP, RAR, 7Z) mediante herramientas comunes
```
</> ATT&CK: T1560, T1041  - yaml
title: Suspicious Archive Creation for Exfiltration Preparation
id: b7a7c9c2-8f2e-4d3b-9e2c-archive-exfil-001
status: experimental
description: >
  Detecta la creación de archivos comprimidos (ZIP, RAR, 7Z) mediante herramientas comúnmente utilizadas en escenarios de ataque, como 7-Zip, WinRAR o PowerShell. Técnicas MITRE ATT&CK: MITRE ATT&CK: T1560 (Archive Collected Data), T1041 (Exfiltration Over C2 Channel)
references:
  - https://attack.mitre.org/techniques/T1560/
  - https://attack.mitre.org/techniques/T1041/
tags:
  - attack.exfiltration
  - attack.collection
  - attack.t1560
  - attack.t1041
logsource:
  product: windows
detection:
  selection_tools:
    Image|endswith:
      - '\7z.exe'
      - '\7za.exe'
      - '\rar.exe'
      - '\winrar.exe'
  selection_cmd:
    CommandLine|contains:
      - '.zip'
      - '.rar'
      - '.7z'
  selection_ps:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'Compress-Archive'
  condition: (selection_tools and selection_cmd) or selection_ps
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Uso legítimo de herramientas de compresión por usuarios o administradores
  - Procesos automatizados de backup o empaquetado de logs
  - Instaladores de software que generan archivos comprimidos
level: medium
```

2️⃣    
</> 
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

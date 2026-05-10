<H1>EXFILTRATION & IMPACT</H1> 

### Exfiltration & Impact


1️⃣    
</> Detecta la creación de archivos comprimidos (ZIP, RAR, 7Z) mediante herramientas comunes
```
</> ATT&CK: T1560, T1041  - yaml
title: Suspicious Archive Creation for Exfiltration Preparation
id: b7a7c9c2-8f2e-4d3b-9e2c-archive-exfil-001
status: experimental
description: Detecta la creación de archivos comprimidos (ZIP, RAR, 7Z) mediante herramientas comúnmente utilizadas en escenarios de ataque, como 7-Zip, WinRAR o PowerShell. Técnicas MITRE ATT&CK: MITRE ATT&CK: T1560 (Archive Collected Data), T1041 (Exfiltration Over C2 Channel)
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
</> Detecta la ejecución de 7-Zip desde procesos padre sospechosos
```    
</> ATT&CK: T1560, T1059 - yaml
title: Suspicious 7-Zip Usage with Suspicious Parent Process
id: 8c3d2a5f-9e12-4c8a-b7a1-7zip-parent-003
status: experimental
description: Detecta la ejecución de 7-Zip (7z.exe o 7za.exe) para la creación o manipulación de archivos comprimidos cuando es iniciado por intérpretes de comandos o scripts como cmd.exe, powershell.exe o wscript.exe. Este patrón es indicativo de actividades automatizadas que pueden estar relacionadas con la recopilación y preparación de datos para su exfiltración. Técnicas MITRE ATT&CK: T1560 (Archive Collected Data), T1059 (Command and Scripting Interpreter)
references:
  - https://attack.mitre.org/techniques/T1560/
  - https://attack.mitre.org/techniques/T1059/
tags:
  - attack.collection 
  - attack.execution
  - attack.t1560
  - attack.t1059
logsource:
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\7z.exe'
      - '\7za.exe'
  selection_args:
    CommandLine|contains:
      - ' a '
      - ' u '
      - ' x '
  selection_parent:
    ParentImage|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
  filter_noise:
    ParentImage|endswith:
      - '\explorer.exe'
  condition: selection_image and selection_args and selection_parent and not filter_noise
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
  - CurrentDirectory
falsepositives:
  - Scripts administrativos legítimos que utilizan 7-Zip desde cmd o PowerShell
  - Herramientas de despliegue o automatización (SCCM, Intune, scripts IT)
level: medium
```

3️⃣    
</> Detecta el uso de comandos de copia de archivos cuando el destino son carpetas temporales o inusuales
```
</> ATT&CK: T1074, T1560, T1059 - yaml
title: Suspicious File Copy to Temporary or Unusual Locations
id: e3b7c5a1-2d8f-4a9c-a6e3-copy-temp-staging-005
status: experimental
description: Detecta el uso de comandos de copia de archivos (copy, xcopy, robocopy) ejecutados desde intérpretes de comandos o scripting cuando el destino corresponde a carpetas temporales o ubicaciones inusuales. Este comportamiento es indicativo de actividades de staging de datos antes de su posible exfiltración, especialmente cuando se realiza de forma automatizada. Técnicas MITRE ATT&CK: T1074 (Data Staged), T1560 (Archive Collected Data), T1059 (Command and Scripting Interpreter)
references:
  - https://attack.mitre.org/techniques/T1074/
  - https://attack.mitre.org/techniques/T1560/
  - https://attack.mitre.org/techniques/T1059/
tags:
  - attack.collection
  - attack.exfiltration
  - attack.t1074
  - attack.t1560
  - attack.t1059
logsource:
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_cmd_copy:
    CommandLine|contains:
      - ' copy '
      - ' xcopy '
      - ' robocopy '
  selection_recursive:
    CommandLine|contains:
      - ' /E '
      - ' /S '
      - ' /MIR '
  selection_destination:
    CommandLine|contains:
      - '\\AppData\\Local\\Temp\\'
      - '\\Windows\\Temp\\'
      - '\\Temp\\'
      - '\\Public\\'
      - '\\ProgramData\\'
  filter_noise:
    ParentImage|endswith:
      - '\explorer.exe'
  condition: selection_parent and selection_cmd_copy and selection_recursive and selection_destination and not filter_noise
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
  - CurrentDirectory
falsepositives:
  - Scripts legítimos de IT que copian datos a carpetas temporales durante instalaciones o despliegues
  - Herramientas de actualización de software que utilizan directorios temporales
  - Procesos automatizados de staging en entornos de desarrollo controlados
level: medium
```

4️⃣    
</> Detecta conexiones salientes de procesos poco habituales o intérpretes de comandos/scripting.
```
</> ATT&CK: T1041, T1071, T1059 - yaml
title: Suspicious Outbound Connection to External Network from Uncommon Process
id: a9f3d6b2-5c7e-4e81-92c4-external-conn-006
status: experimental
description: Detecta conexiones salientes hacia direcciones IP externas (públicas) iniciadas por procesos poco habituales o intérpretes de comandos/scripting como cmd.exe, powershell.exe o wscript.exe. Este comportamiento puede indicar actividad de exfiltración de datos o comunicación con infraestructura de comando y control (C2). Técnicas MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel), T1071 (Application Layer Protocol), T1059 (Command and Scripting Interpreter).
references:
  - https://attack.mitre.org/techniques/T1041/
  - https://attack.mitre.org/techniques/T1071/
  - https://attack.mitre.org/techniques/T1059/
tags:
  - attack.exfiltration
  - attack.command_and_control
  - attack.t1041
  - attack.t1071
  - attack.t1059
logsource:
  product: windows
detection:
  selection_external_ip:
    DestinationIp|notstartswith:
      - '10.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.20.'
      - '172.21.'
      - '172.22.'
      - '172.23.'
      - '172.24.'
      - '172.25.'
      - '172.26.'
      - '172.27.'
      - '172.28.'
      - '172.29.'
      - '172.30.'
      - '172.31.'
      - '192.168.'
      - '127.'
  selection_suspicious_process:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
  filter_common_processes:
    Image|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
      - '\outlook.exe'
      - '\teams.exe'
      - '\onedrive.exe'
  condition: selection_external_ip and selection_suspicious_process and not filter_common_processes
fields:
  - Image
  - DestinationIp
  - DestinationPort
  - CommandLine
  - User
falsepositives:
  - Scripts administrativos que realizan conexiones legítimas a APIs externas
  - Herramientas de automatización o monitorización
  - Uso legítimo de PowerShell para descargas o consultas web
level: medium
```

5️⃣    
</> Detecta el uso de PowerShell para realizar posibles subidas o exfiltración de datos.
```
</> ATT&CK: T1041, T1059.001, T1105 - yaml
title: Suspicious PowerShell File Upload or Data Exfiltration Activity
id: f6c92e41-3a7b-4d55-8e91-ps-upload-007
status: experimental
description: Detecta el uso de PowerShell para realizar posibles subidas de datos (upload) o exfiltración mediante funciones, cmdlets o técnicas comunes como WebClient, Invoke-WebRequest o Invoke-RestMethod. Este comportamiento es característico de ataques que utilizan PowerShell para transferir información hacia sistemas externos o infraestructura de comando y control (C2). Técnicas MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel), T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)
references:
  - https://attack.mitre.org/techniques/T1041/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1105/
tags:
  - attack.exfiltration
  - attack.command_and_control
  - attack.execution
  - attack.t1041
  - attack.t1059.001
  - attack.t1105
logsource:
  product: windows
detection:
  selection_powershell:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_exfil_cmdlets:
    CommandLine|contains:
      - 'Invoke-WebRequest'
      - 'Invoke-RestMethod'
      - 'System.Net.WebClient'
      - 'UploadFile'
      - 'UploadString'
      - 'Post'
      - 'Put'
  selection_suspicious_args:
    CommandLine|contains:
      - 'http://'
      - 'https://'
  filter_noise:
    CommandLine|contains:
      - 'Microsoft.com'
      - 'WindowsUpdate'
      - 'Azure'
  condition: selection_powershell and selection_exfil_cmdlets and selection_suspicious_args and not filter_noise
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
  - DestinationIp
  - DestinationPort
falsepositives:
  - Scripts legítimos que interactúan con APIs REST
  - Herramientas de automatización que envían datos a servicios cloud corporativos
  - Integraciones DevOps (CI/CD, monitoring, etc.)
level: medium
```

6️⃣
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

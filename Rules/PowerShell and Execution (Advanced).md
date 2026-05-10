<H1>POWER SHELL & EXECUTION (ADVANCED)</H1>

### PowerShell & Execution


:one:   
</> Ejecución sospechosa de PowerShell usando comandos codificados junto con patrones asociados con malware, movimiento lateral o evasión de defensa
```
</> AAT&CK: T1059.001, T1027 - yaml
title: Suspicious PowerShell Encoded Command Execution
id: 14r92d-ps-encodedcommand-002
status: experimental
description: Detecta ejecución sospechosa de PowerShell usando comandos codificados junto con patrones asociados con malware, movimiento lateral o evasión de defensa.
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
   
:two:    
</> Detecta uso sospechoso de DownloadString en PowerShell combinado con la ejecución de patrones comunmente asociados con entrega de malware y/o ataques fileless.
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


3️⃣   
</> Detecta potencial uso sospechoso de Invoke-WebRequest en PowerShell, comunmente usado para descargar payloads
```
</> AAT&CK: T1105 - yaml -
title: Suspicious PowerShell Invoke-WebRequest Usage
id: 3c8b9d6a-ps-iwr-suspicious
status: experimental
description: Detecta potencial uso sospechoso de Invoke-WebRequest en PowerShell, comunmente usado para descargar payloads
references:
  - https://attack.mitre.org/techniques/T1105/
author: Emilio Rico Ruiz (optimized)
date: 2026/05/07
logsource:
  product: windows
  category: process_creation
detection:
  selection_cmdlet:
    CommandLine|contains:
      - Invoke-WebRequest
      - iwr
  selection_suspicious_flags:
    CommandLine|contains:
      - "-Uri http"
      - "-OutFile"
      - "-UseBasicParsing"
  selection_parent:
    ParentImage|endswith:
      - \cmd.exe
      - \powershell.exe
      - \wscript.exe
      - \mshta.exe
  selection_http:
    CommandLine|contains:
      - "http://"
      - "https://"
  filter_known_good:
    Image|endswith:
      - \MicrosoftEdgeUpdate.exe
      - \OneDrive.exe
  condition: selection_cmdlet and selection_http and (selection_suspicious_flags or selection_parent) and not filter_known_good
fields:
  - CommandLine
  - ParentImage
  - Image
falsepositives:
  - Administrative scripts using Invoke-WebRequest
  - Software updates or deployment scripts
level: medium
tags:
  - attack.command_and_control
  - attack.t1105
```


4️⃣    
</> Detecta ejecucionn sospechosa de PowerShell desde aplicaciones Microsoft Offices, comunmente asociadas al uso de macros
```
</> AAT&CK: T1204, T1059.001 - yaml
title: Suspicious PowerShell Spawned by Office Applications
id: 91b3e0f4-office-pshell
status: experimental
description: Detecta ejecucionn sospechosa de PowerShell desde aplicaciones Microsoft Offices, comunmente asociadas al uso de macros
references:
  - https://attack.mitre.org/techniques/T1059/001/
date: 2026/05/07
logsource:
  product: windows
  category: process_creation
detection:
  selection_office_parent:
    ParentImage|endswith:
      - \winword.exe
      - \excel.exe
      - \powerpnt.exe
      - \outlook.exe
  selection_powershell:
    Image|endswith:
      - \powershell.exe
      - \pwsh.exe
  selection_suspicious_args:
    CommandLine|contains:
      - "-EncodedCommand"
      - "-enc"
      - "IEX"
      - "Invoke-Expression"
      - "DownloadString"
      - "Invoke-WebRequest"
      - "iwr"
  selection_hidden_execution:
    CommandLine|contains:
      - "-WindowStyle Hidden"
      - "-w hidden"
      - "-nop"
      - "-noprofile"
  filter_legit_paths:
    ParentImage|contains:
      - "Program Files\\Microsoft Office\\root\\Office"
  condition: selection_office_parent and selection_powershell and (selection_suspicious_args or selection_hidden_execution)
fields:
  - Image
  - ParentImage
  - CommandLine
falsepositives:
  - Rare administrative scripts triggered via Office add-ins
  - Custom enterprise macros (should be baselined)
level: high
tags:
  - attack.execution
  - attack.t1059.001
``
```

:five:    
</> Detecta uso sospechoso de Invoke-Expression (IEX) en PowerShell
```
</> AAT&CK: T1059.001 - yaml
title: Suspicious PowerShell Invoke-Expression (IEX) Usage
id: 7c2f1a9d-ps-iex
status: experimental
description: Detecta uso sospechoso de Invoke-Expression (IEX) en PowerShell, comunmente usado para ejecutar payloads descargados u ofuscados
references:
  - https://attack.mitre.org/techniques/T1059/001/
date: 2026/05/07
logsource:
  product: windows
  category: process_creation
detection:
  selection_iex:
    CommandLine|contains:
      - "IEX"
      - "Invoke-Expression"
  selection_download:
    CommandLine|contains:
      - "DownloadString"
      - "Invoke-WebRequest"
      - "iwr"
      - "Net.WebClient"
  selection_encoded:
    CommandLine|contains:
      - "-EncodedCommand"
      - "-enc"
  selection_obfuscation:
    CommandLine|contains:
      - "FromBase64String"
      - "New-Object"
  selection_hidden:
    CommandLine|contains:
      - "-nop"
      - "-noprofile"
      - "-w hidden"
  condition: selection_iex and (selection_download or selection_encoded or selection_obfuscation or selection_hidden)
fields:
  - CommandLine
  - ParentImage
  - Image
falsepositives:
  - Administrative scripts using Invoke-Expression (rare in production)
  - Developer scripts or automation tools
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

6️⃣    
</> Detecta la ejecución de PowerShell con parámetros de ocultación o evasión como ventanas ocultas
```
</> AAT&CK: T1564, T1059.001 - yaml
title: PowerShell Hidden or Silent Execution Flags
id: 5a6b9c21-ps-hidden, 
status: experimental
description: Detecta la ejecución de PowerShell con parámetros de ocultación o evasión como ventanas ocultas o sin carga de perfil, técnica común en ataques para evitar la detección
references:
  - https://attack.mitre.org/techniques/T1059/001/
date: 2026/05/07
logsource:
  product: windows
  category: process_creation
detection:
  selection_powershell:
    Image|endswith:
      - \powershell.exe
      - \pwsh.exe
  selection_flags:
    CommandLine|contains:
      - "-w hidden"
      - "-windowstyle hidden"
      - "-nop"
      - "-noprofile"
  selection_suspicious_context:
    CommandLine|contains:
      - "-enc"
      - "-EncodedCommand"
      - "IEX"
      - "Invoke-Expression"
      - "DownloadString"
      - "Invoke-WebRequest"
      - "iwr"
  selection_parent:
    ParentImage|endswith:
      - \winword.exe
      - \excel.exe
      - \outlook.exe
      - \cmd.exe
      - \wscript.exe
      - \mshta.exe
  condition: selection_powershell and selection_flags and (selection_suspicious_context or selection_parent)
fields:
  - Image
  - CommandLine
  - ParentImage
falsepositives:
  - Scripts administrativos que usan -noprofile o ejecución sin ventana visible
  - Herramientas de automatización legítimas
level: medium
tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1564
```

:seven:     
</> Detecta el uso de comandos PowerShell codificados o cadenas largas en Base64 en la línea de comandos
```
</> AAT&CK: T1027 - yaml
title: Suspicious PowerShell Encoded Command or Long Base64 String
id: 8f4c2a7d-ps-base64
status: experimental
description: Detecta el uso de comandos PowerShell codificados o cadenas largas en Base64 en la línea de comandos
references:
  - https://attack.mitre.org/techniques/T1059/001/
date: 2026/05/07
logsource:
  product: windows
  category: process_creation
detection:
  selection_powershell:
    Image|endswith:
      - \powershell.exe
      - \pwsh.exe
  selection_encoded_flag:
    CommandLine|contains:
      - "-enc"
      - "-EncodedCommand"
  selection_base64_pattern:
    CommandLine|re: "[A-Za-z0-9+/]{150,}={0,2}"
  selection_additional_context:
    CommandLine|contains:
      - "IEX"
      - "Invoke-Expression"
      - "FromBase64String"
      - "DownloadString"
      - "Invoke-WebRequest"
  condition: selection_powershell and (selection_encoded_flag or (selection_base64_pattern and selection_additional_context))
fields:
  - Image
  - CommandLine
  - ParentImage
falsepositives:
  - Scripts administrativos que utilizan comandos codificados
  - Herramientas de automatización que pasan datos largos en Base64
level: high
tags:
  - attack.execution
  - attack.t1027
```

8️⃣    
</> Detecta ejecuciones de cmd.exe con el parámetro /c junto a patrones comúnmente asociados a actividades maliciosas
```
</> AAT&CK: T1059.003 - yaml
title: Suspicious CMD Execution with Potential Malicious Context
id: d3f9a2b1-cmd-suspicious
status: experimental
description: Detecta ejecuciones de cmd.exe con el parámetro /c junto a patrones comúnmente asociados a actividades maliciosas, como ejecución encadenada, descarga de payloads o invocación de herramientas de scripting
references:
  - https://attack.mitre.org/techniques/T1059/
date: 2026/05/07
logsource:
  product: windows
  category: process_creation
detection:
  selection_cmd:
    Image|endswith: \cmd.exe
  selection_flag:
    CommandLine|contains: "/c"
  selection_suspicious_commands:
    CommandLine|contains:
      - "powershell"
      - "bitsadmin"
      - "certutil"
      - "mshta"
      - "wscript"
      - "cscript"
      - "rundll32"
  selection_chaining:
    CommandLine|contains:
      - "&&"
      - "|"
  selection_network_indicators:
    CommandLine|contains:
      - "http://"
      - "https://"
  selection_parent:
    ParentImage|endswith:
      - \winword.exe
      - \excel.exe
      - \outlook.exe
      - \mshta.exe
      - \wscript.exe
      - \powershell.exe
  condition: selection_cmd and selection_flag and (selection_suspicious_commands or selection_network_indicators or selection_chaining or selection_parent)
fields:
  - Image
  - CommandLine
  - ParentImage
falsepositives:
  - Scripts administrativos complejos que usan cmd.exe como wrapper
  - Instaladores de software o herramientas IT
  - Tareas automatizadas corporativas
level: medium
tags:
  - attack.execution
  - attack.t1059
```

9️⃣    
</> Detecta el uso sospechoso de rundll32.exe para ejecutar contenido remoto o scripts
```
</> AAT&CK: T1218.011 - yaml
title: Suspicious Rundll32 Remote or Script Execution
id: a1c7b3e9-rundll32-remote
status: experimental
description: Detecta el uso sospechoso de rundll32.exe para ejecutar contenido remoto o scripts, técnica utilizada frecuentemente para evasión y ejecución de código malicioso
references:
  - https://attack.mitre.org/techniques/T1218/011/
date: 2026/05/07
logsource:
  product: windows
  category: process_creation
detection:
  selection_rundll32:
    Image|endswith: \rundll32.exe
  selection_remote:
    CommandLine|contains:
      - "http://"
      - "https://"
  selection_script_execution:
    CommandLine|contains:
      - "javascript:"
      - "vbscript:"
      - "mshtml"
  selection_suspicious_dll:
    CommandLine|contains:
      - ".dll,"
      - ".dll "
  selection_parent:
    ParentImage|endswith:
      - \winword.exe
      - \excel.exe
      - \outlook.exe
      - \mshta.exe
      - \wscript.exe
      - \cmd.exe
      - \powershell.exe
  condition: selection_rundll32 and (selection_remote or selection_script_execution or (selection_suspicious_dll and selection_parent))
fields:
  - Image
  - CommandLine
  - ParentImage
falsepositives:
  - Uso legítimo de rundll32 con DLLs internas del sistema
  - Scripts administrativos avanzados poco comunes
level: high
tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1218.011
```

:one:0️⃣    
</> Detecta el uso sospechoso de regsvr32.exe para ejecutar scripts remotos mediante la técnica Squiblydoo
```
</> AAT&CK: T1218.010 - yaml
title: Suspicious Regsvr32 Remote Script Execution (Squiblydoo)
id: e4b2c6f8-regsvr32-remote
status: experimental
description: Detecta el uso sospechoso de regsvr32.exe para ejecutar scripts remotos mediante la técnica Squiblydoo, comúnmente utilizada para evasión y ejecución de código sin archivos
references:
  - https://attack.mitre.org/techniques/T1218/010/
date: 2026/05/07
logsource:
  product: windows
  category: process_creation
detection:
  selection_regsvr32:
    Image|endswith: \regsvr32.exe
  selection_remote:
    CommandLine|contains:
      - "http://"
      - "https://"
  selection_squiblydoo:
    CommandLine|contains:
      - "scrobj.dll"
      - "/i:"
  selection_silent_flags:
    CommandLine|contains:
      - "/s"
      - "/u"
      - "/n"
  selection_parent:
    ParentImage|endswith:
      - \winword.exe
      - \excel.exe
      - \outlook.exe
      - \powershell.exe
      - \cmd.exe
      - \mshta.exe
      - \wscript.exe
  condition: selection_regsvr32 and selection_remote and (selection_squiblydoo or selection_silent_flags or selection_parent)
fields:
  - Image
  - CommandLine
  - ParentImage
falsepositives:
  - Uso legítimo de regsvr32 con scripts remotos internos (muy poco común)
  - Actividades específicas de administración o testing
level: high
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1218.010
```


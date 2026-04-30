<H1> SIGMA RULES </H1>
Las reglas SIGMA son plantillas genéricas para detectar actividad sospechosa en logs.

:triangular_flag_on_post: Piensa en ellas como: “Si pasa esto en los logs → puede ser un ataque”

No están ligadas a una herramienta concreta, para que funciones es necesario convertirlas al formato específico de la herramienta que utilices (Splunk, Elastic, Sentinel, etc.).

Ejemplo sencillo (fichero YAML)

```
title: Uso sospechoso de PowerShell
detection:
  selection:
    Image: powershell.exe
    CommandLine: "*DownloadString*"
  condition: selection
```

¿que inidica esté pseudo-código? Traducción: Si alguien usa PowerShell para descargar cosas → sospechoso


## 50 reglas sigma
A continuación tienes un set de ***50 reglas Sigma*** (simplificadas pero funcionales) listas para usar como base.

Ejemplos de reglas para los siguientes topics

- :clipboard: [Power Shell Execution](#powershell--execution)
- :anchor: [Persistence](Rules/Persistencia.md)
- :ticket: [Privilege Escalation & Credential Access](Rules/Escalado%20de%20Privilegios%20y%20Acceso%20a%20Credenciales.md)
- :ladder: [Lateral Movement & Discovery](Rules/Movimiento%20Lateral%20y%20descubrimiento.md)
- :goal_net: [Exfiltración e Impacto](Rules/Exfiltracion%20e%20Impacto.md)

Más abajo te explico cómo puedes combinarlas en [Reglas más complejas](#reglas--mas--complejas)

⚠️ Importante: Están optimizadas para claridad y uso práctico. Aunque cubren muchas casuísticas, no esperes que cubran el 100% de tus necesidades. Úsalas como plantilla operativa, no hagas un simple copy/paste.

Cada regla está asociada a una (o varias) técnicas de MITRE. La idea es que consultes la técnica que quieras cubrir y averigües qué data source y/o que log registra la actividad que te permita investigar si has recibido ese ataque.





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




### Reglas complejas 

Sea libre de combinar las reglas en reglas más complejas para activar las alarmas.
Por ejemplo:

```
</> yaml
detection:
  selection1:
    Image|endswith: powershell.exe
  selection2:
    CommandLine|contains: "EncodedCommand"
  filter:
    User: "SYSTEM"
  condition: selection1 AND selection2 AND NOT filter
```

Este ejemplo haría saltar una alarma si y solo si se cumplen las tres condiciones

```
powershell.exe
AND encoded command
AND user != SYSTEM
```


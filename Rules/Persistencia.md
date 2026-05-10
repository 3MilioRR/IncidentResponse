<h1>PERSISTENCIA</h1>

### Persistence

:one:    
</> Detecta la creación de tareas programadas en sistemas Windows
```
</> ATT&CK: T1053.005 - yaml
title: Scheduled Task Creation
description: Detecta la creación de tareas programadas en sistemas Windows mediante el uso de la utilidad schtasks.exe. Ojo con falsos positivos porque los administradores lo usan comunmente de forma legítima. Relacionado con MITRE ATT&CK T1053.005 (Scheduled Task/Job: Scheduled Task).
logsource:
  product: windows
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains|all:
      - 'schtasks'
      - '/create'
  filter_legitimate:
    CommandLine|contains:
      - '\Microsoft\Windows\'
      - 'OneDrive'
      - 'GoogleUpdate'
      - 'Adobe'
      - 'Teams'
  condition: selection and not filter_legitimate
falsepositives:
  - Actividad administrativa legítima
  - Instalación o actualización de software
level: medium
```

2️⃣   
</> Detecta la modificación o creación de claves de ejecución automática en el registro de Windows (Run Keys)
```
</> ATT&CK: T1547.001 - yaml
title: Registry Run Key Persistence
description: Detecta la modificación o creación de claves de ejecución automática en el registro de Windows (Run Keys). Ojo nuevamente porque las aplicaciones instaladas tambien dejan marca en el registro, por lo que debe analizarse el contexto y la ruta del binario asociado. Relacionado con MITRE ATT&CK T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder).
logsource:
  product: windows
detection:
  selection:
    TargetObject|contains:
      - '\Software\Microsoft\Windows\CurrentVersion\Run'
      - '\Software\Microsoft\Windows\CurrentVersion\RunOnce'
  filter_legitimate:
    Details|contains:
      - 'OneDrive'
      - 'Teams'
      - 'SecurityHealth'
      - 'Windows Defender'
      - 'GoogleUpdate'
      - 'Adobe'
    Image|endswith:
      - '\msiexec.exe'
      - '\setup.exe'
      - '\install.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Instalación o actualización de software legítimo
  - Herramientas de gestión IT
level: medium
```

3️⃣     
</> Detecta la instalación de nuevos servicios en sistemas Windows mediante el evento 7045 del registro de eventos de sistemas
```
</> ATT&CK: T1543.003 - yaml
title: New Service Installed
description: Detecta la instalación de nuevos servicios en sistemas Windows mediante el evento 7045 del registro de eventos de sistemas. Es ampliamente utilizada por software legítimo, por lo que es necesario analizar el nombre, la RUTA del binario y el contexto de ejecución. Relacionado con MITRE ATT&CK T1543.003 (Create or Modify System Process: Windows Service).
logsource:
  product: windows
detection:
  selection:
    EventID: 7045
  filter_legitimate:
    ServiceFileName|contains:
      - 'Program Files'
      - 'Windows\\System32'
    ServiceName|contains:
      - 'Windows'
      - 'Microsoft'
      - 'Adobe'
      - 'Google'
      - 'Teams'
  filter_noise:
    ServiceFileName|contains:
      - 'C:\\Windows\\SoftwareDistribution\\'
      - 'C:\\ProgramData\\Microsoft\\'
  condition: selection and not (filter_legitimate or filter_noise)
fields:
  - ServiceName
  - ServiceFileName
  - AccountName
falsepositives:
  - Instalación de software legítimo
  - Herramientas de administración remota o despliegue
level: medium
```

4️⃣    
</> Detecta servicios configurados para ejecutarse desde rutas inusuales, potencialmente maliciosas, temporales o ubicaciones de datos.
```
</> ATT&CK: T1543.003 - yaml
title: Suspicious Service Path
description: Detecta servicios de Windows configurados para ejecutarse desde rutas inusuales o potencialmente maliciosas como directorios de usuario (AppData), temporales o ubicaciones de datos (ProgramData), lo cual es indicativo de abuso para persistencia por parte de malware. Esta detección se enfoca en servicios persistentes (inicio automático) y excluye ubicaciones y proveedores legítimos conocidos para reducir falsos positivos. Relacionado con MITRE ATT&CK T1543.003 (Create or Modify System Process: Windows Service).
logsource:
  product: windows
detection:
  selection_paths:
    ImagePath|contains:
      - '\AppData\'
      - '\Users\Public\'
      - '\Temp\'
      - '\ProgramData\'
  selection_persistence:
    StartType:
      - 'Auto Start'
      - 'Automatic'
      - 'Boot'
  filter_legitimate_paths:
    ImagePath|startswith:
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
      - 'C:\Windows\System32\'
  filter_known_vendors:
    ImagePath|contains:
      - 'Microsoft\\'
      - 'Windows Defender'
      - 'OneDrive'
      - 'Google\\'
      - 'Adobe\\'
      - 'Teams\\'
      - 'Cisco\\'
      - 'CrowdStrike\\'
      - 'SentinelOne\\'
  filter_deployment_tools:
    ImagePath|contains:
      - '\ccmcache\'        # SCCM
      - '\Windows\Temp\'
      - '\Package Cache\'
      - '\ProgramData\Package Cache\'
  condition: selection_paths and selection_persistence
             and not (filter_legitimate_paths or filter_known_vendors or filter_deployment_tools)
fields:
  - ServiceName
  - ImagePath
  - StartType
  - AccountName
falsepositives:
  - Software corporativo instalado en rutas no estándar
  - Herramientas de seguridad o EDR
  - Soluciones de despliegue (SCCM, Intune, scripts IT)
level: high
```

:five:   
</> Detecta la creación de suscripciones persistentes de WMI (Windows Management Instrumentation)
```
</> ATT&CK: T1546.003 - yaml
title: WMI Persistence
description: Detecta la creación de suscripciones persistentes de WMI (Windows Management Instrumentation), utilizadas habitualmente por atacantes para mantener persistencia mediante filtros y consumidores de eventos. Relacionado con MITRE ATT&CK T1546.003 (Event Triggered Execution: Windows Management Instrumentation Event Subscription).
logsource:
  product: windows
detection:
  selection_event:
    EventID: 5861
  selection_wmi_objects:
    Operation|contains:
      - 'Created'
      - 'Creation'
  selection_suspicious_namespace:
    Namespace|contains:
      - 'root\\subscription'
  filter_legitimate:
    User|contains:
      - 'NT AUTHORITY\\SYSTEM'
  filter_known_tools:
    Operation|contains:
      - 'Microsoft'
      - 'SCOM'
      - 'ConfigMgr'
      - 'SCCM'
  condition: selection_event
             and selection_wmi_objects
             and selection_suspicious_namespace
             and not (filter_legitimate or filter_known_tools)
fields:
  - User
  - Operation
  - Namespace
  - Query
falsepositives:
  - Herramientas de administración (SCCM, SCOM)
  - Scripts legítimos de monitorización
  - Automatizaciones internas de IT
level: high
```

```
</> ATT&CK:  - yaml
title: Startup Folder Modification
logsource: {product: windows}
detection:
  selection:
    TargetFilename|contains: "Startup"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: DLL in Temp Execution
logsource: {product: windows}
detection:
  selection:
    Image|contains: ".dll"
    CommandLine|contains: "Temp"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Autorun Registry Modification
logsource: {product: windows}
detection:
  selection:
    TargetObject|contains: "RunOnce"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Service Modification
logsource: {product: windows}
detection:
  selection:
    EventID: 7040
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Suspicious Scheduled Task Path
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "AppData"
  condition: selection
```


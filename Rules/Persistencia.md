<h1>PERSISTENCIA</h1>

### Persistence

Las técnicas de persistencia son métodos utilizados por ciberatacantes para mantener el acceso continuo a un sistema comprometido incluso después de reinicios, cambios de contraseñas o cierres de sesión. Estas tácticas permiten a los intrusos asegurar su permanencia a largo plazo para robar datos, espiar o moverse lateralmente sin ser detectados.

Aquí hay algunas reglas que detectan estos métodos.

1. Detecta la creación de tareas programadas en sistemas Windows [🔗](#detecta-la-creación-de-tareas-programadas-en-sistemas-Windows)
2. Detecta la modificación o creación de claves de ejecución automática en el registro de Windows [🔗](#detecta-la-modificación-o-creación-de-claves-de-ejecución-automática-en-el-registro-de-Windows)
3. 

<H3>REGLAS</H3>

1️⃣    
### Detecta la creación de tareas programadas en sistemas Windows
</> ATT&CK: T1053.005 - yaml
```
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
### Detecta la modificación o creación de claves de ejecución automática en el registro de Windows
</> ATT&CK: T1547.001 - yaml
```
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

5️⃣   
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

6️⃣    
</> Detecta la creación o modificación de archivos en las carpetas de inicio automático de Windows (Startup Folder)
```
</> ATT&CK: T1547.001 - yaml
title: Startup Folder Modification
description: Detecta la creación o modificación de archivos en las carpetas de inicio automático de Windows (Startup Folder). La regla se enfoca en ubicaciones específicas de inicio y excluye rutas y procesos legítimos habituales para reducir falsos positivos. Relacionado con MITRE ATT&CK T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder).
logsource:
  product: windows
detection:
  selection_paths:
    TargetFilename|contains:
      - '\Microsoft\Windows\Start Menu\Programs\Startup\'
      - '\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\'
  selection_suspicious_ext:
    TargetFilename|endswith:
      - '.exe'
      - '.bat'
      - '.cmd'
      - '.ps1'
      - '.lnk'
      - '.vbs'
  filter_legitimate_process:
    Image|endswith:
      - '\explorer.exe'
      - '\msiexec.exe'
      - '\setup.exe'
      - '\install.exe'
  filter_known_vendors:
    TargetFilename|contains:
      - 'OneDrive'
      - 'Teams'
      - 'Microsoft'
      - 'Google'
      - 'Adobe'
  condition: selection_paths
             and selection_suspicious_ext
             and not (filter_legitimate_process or filter_known_vendors)
fields:
  - TargetFilename
  - Image
  - User
falsepositives:
  - Instalación o actualización de software legítimo
  - Scripts corporativos de login
  - Herramientas de despliegue IT
level: high
```

7️⃣   
</> Detecta la ejecución de bibliotecas DLL desde directorios temporales de Windows
```
</> ATT&CK: T1574.001 - yaml
title: DLL in Temp Execution
description: Detecta la ejecución de bibliotecas DLL desde directorios temporales de Windows. Este es un comportamiento poco habitual en software legítimo y comúnmente asociado a técnicas de evasión y persistencia empleadas por malware. La regla se centra en procesos que cargan DLL desde rutas temporales y excluye casos conocidos para reducir falsos positivos. Relacionado con MITRE ATT&CK T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking).
logsource:
  product: windows
detection:
  selection_dll_execution:
    CommandLine|contains:
      - '.dll'
  selection_temp_paths:
    CommandLine|contains:
      - '\Temp\'
      - '\AppData\Local\Temp\'
      - '\Windows\Temp\'
  selection_suspicious_parent:
    ParentImage|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
  filter_legitimate:
    Image|endswith:
      - '\msiexec.exe'
      - '\setup.exe'
      - '\install.exe'
  filter_known_patterns:
    CommandLine|contains:
      - 'Windows\\Installer'
      - 'Package Cache'
  condition: selection_dll_execution
             and selection_temp_paths
             and selection_suspicious_parent
             and not (filter_legitimate or filter_known_patterns)
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Instaladores legítimos ejecutando DLL temporalmente
  - Herramientas de despliegue (SCCM, Intune)
  - Scripts administrativos avanzados
level: high
```

8️⃣    
</> Detecta la modificación o creación de entradas en la clave de registro RunOnce de Windows
```
</> ATT&CK: T1547.001 - yaml
title: Autorun Registry Modification
description: Detecta la modificación o creación de entradas en la clave de registro RunOnce de Windows, utilizada para ejecutar programas automáticamente en el próximo inicio de sesión. Esta técnica es utilizada por software legítimo así que deberían incluirse filtros y rutas para mejorar la precisión. Relacionado con MITRE ATT&CK T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder).
logsource:
  product: windows
detection:
  selection_key:
    TargetObject|contains:
      - '\Software\Microsoft\Windows\CurrentVersion\RunOnce'
      - '\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
  selection_suspicious_paths:
    Details|contains:
      - '\AppData\'
      - '\Temp\'
      - '\Users\Public\'
      - '\ProgramData\'
  filter_legitimate_installers:
    Image|endswith:
      - '\msiexec.exe'
      - '\setup.exe'
      - '\install.exe'
  filter_known_vendors:
    Details|contains:
      - 'Microsoft'
      - 'Windows Defender'
      - 'OneDrive'
      - 'Google'
      - 'Adobe'
      - 'Teams'
  filter_system_context:
    User|contains:
      - 'NT AUTHORITY\\SYSTEM'
  condition: selection_key
             and selection_suspicious_paths
             and not (filter_legitimate_installers or filter_known_vendors or filter_system_context)
fields:
  - TargetObject
  - Details
  - Image
  - User
falsepositives:
  - Instalaciones legítimas de software
  - Actualizaciones automáticas
  - Scripts internos de IT
level: high
```

9️⃣    
</> Detecta modificaciones en servicios de Windows mediante el evento 7040,
```
</> ATT&CK: T1562.001 - yaml
title: Service Modification
description: Detecta modificaciones en servicios de Windows mediante el evento 7040, incluyendo cambios a inicio automático (persistencia) y deshabilitación de servicios de seguridad. La detección combina múltiples indicadores como rutas sospechosas, binarios no firmados y nombres de servicios críticos para reducir falsos positivos. Relacionado con MITRE ATT&CK T1543.003 (Create or Modify System Process: Windows Service) y T1562.001 (Impair Defenses: Disable or Modify Tools).
logsource:
  product: windows
detection:
  selection_event:
    EventID: 7040
  selection_persistence:
    StartType:
      - 'Auto Start'
      - 'Automatic'
      - 'Boot'
  selection_disabled:
    StartType:
      - 'Disabled'
  selection_security_services:
    ServiceName|contains:
      - 'Defender'
      - 'Sense'
      - 'WdNisSvc'
      - 'WinDefend'
      - 'SecurityHealth'
      - 'MpsSvc'           # Windows Firewall
      - 'wscsvc'           # Security Center
      - 'Sophos'
      - 'CrowdStrike'
      - 'Sentinel'
      - 'CarbonBlack'
      - 'McAfee'
      - 'Trend'
      - 'ESET'
  selection_suspicious_paths:
    ImagePath|contains:
      - '\AppData\'
      - '\Temp\'
      - '\Users\Public\'
      - '\ProgramData\'
  selection_unsigned:
    Signed: 'false'
    SignatureStatus:
      - 'Invalid'
      - 'Unknown'
  filter_legitimate_services:
    ServiceName|contains:
      - 'Windows Update'
      - 'TrustedInstaller'
  filter_standard_paths:
    ImagePath|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
  condition: selection_event and (
                (selection_persistence and (selection_suspicious_paths or selection_unsigned))
                or
                (selection_disabled and selection_security_services)
             )
             and not (filter_legitimate_services or filter_standard_paths)
fields:
  - ServiceName
  - ImagePath
  - StartType
  - User
  - Signed
  - SignatureStatus
falsepositives:
  - Cambios administrativos en servicios
  - Desactivación controlada de herramientas de seguridad
  - Actualizaciones o mantenimiento de sistemas
level: high
```

:one:0️⃣    
</> Detecta la creación de tareas programadas en Windows que hacen referencia a binarios ubicados en rutas sospechosas
```
</> ATT&CK: T1053.005 - yaml
title: Suspicious Scheduled Task Path
description: Detecta la creación de tareas programadas en Windows que hacen referencia a binarios ubicados en rutas sospechosas como AppData. La regla se centra en tareas creadas mediante herramientas típicas y excluye casos legítimos conocidos para mejorar la precisión. Relacionado con MITRE ATT&CK T1053.005 (Scheduled Task/Job: Scheduled Task).
logsource:
  product: windows
detection:
  selection_task_creation:
    Image|endswith:
      - '\schtasks.exe'
      - '\powershell.exe'
      - '\cmd.exe'
  selection_creation_flag:
    CommandLine|contains:
      - '/create'
      - 'New-ScheduledTask'
      - 'Register-ScheduledTask'
  selection_suspicious_paths:
    CommandLine|contains:
      - '\AppData\'
      - '\Temp\'
      - '\Users\Public\'
      - '\ProgramData\'
  selection_suspicious_ext:
    CommandLine|contains:
      - '.exe'
      - '.ps1'
      - '.bat'
      - '.cmd'
      - '.vbs'
  filter_legitimate:
    CommandLine|contains:
      - '\Microsoft\Windows\'
      - 'OneDrive'
      - 'GoogleUpdate'
      - 'Adobe'
      - 'Teams'
  filter_installers:
    Image|endswith:
      - '\msiexec.exe'
      - '\setup.exe'
      - '\install.exe'
  condition: selection_task_creation
             and selection_creation_flag
             and selection_suspicious_paths
             and selection_suspicious_ext
             and not (filter_legitimate or filter_installers)
fields:
  - Image
  - CommandLine
  - User
falsepositives:
  - Instalaciones de software legítimo
  - Scripts administrativos corporativos
  - Herramientas de despliegue IT (SCCM, Intune)
level: high
```


<H1>LATERAL MOVEMENT & DISCOVERY</H1>
### REGLAS SIGMA: Lateral Movement & Discovery

1. Inicio de sesión de red sospechoso con cuentas privilegiadas o de servicio (logon tipo 3) [🔗](#Inicio-de-sesión-de-red-sospechoso-con-cuentas-privilegiadas-o-de-servicio-(logon-tipo-3))
2. Inicio de sesión remoto RDP sospechoso (logon tipo 10) [🔗](#Inicio-de-sesión-remoto-RDP-sospechoso-logon-tipo-10) 
3. Ejecución sospechosa de PsExec mediante línea de comandos [🔗](#Ejecución-sospechosa-de-PsExec-mediante-línea-de-comandos)
4. Ejecución remota sospechosa vía WMI (WMIC) [🔗](#ejecución-remota-sospechosa-vía-wmi-\\(wmic\\)) 
5. Ejecución remota sospechosa vía WinRM [🔗](#Ejecución-remota-sospechosa-vía-WinRM)
6. Enumeración sospechosa de recursos compartidos [🔗](3Enumeración-sospechosa-de-recursos-compartidos)
7. Uso sospechoso de NLTest para reconocimiento de dominio [🔗](#Uso-sospechoso-de-NLTest-para-reconocimiento-de-dominio)
8. Ejecución sospechosa de ipconfig para descubrimiento de red [🔗](#Ejecución-sospechosa-de-ipconfig-para-descubrimiento-de-red)
9. Ejecución sospechosa de netstat para descubrimiento de red [🔗](#Ejecución-sospechosa-de-netstat-para-descubrimiento-de-red)
10. Ejecución sospechosa del comando whoami [🔗](#Ejecución-sospechosa-del-comando-whoami)


<H3>REGLAS</H3>


1️⃣   
### Inicio de sesión de red sospechoso con cuentas privilegiadas o de servicio (logon tipo 3)
</> ATT&CK: T1021 y T1078 - yaml
```
title: Suspicious Network Logon with Privileged or Service Account
id: 5c7f2b6e-9a4c-4c6e-a73b-2d1e8f4e9134
status: experimental
description: Detecta inicios de sesión de red (LogonType 3) en sistemas Windows asociados a cuentas con características típicas de privilegio o servicio (por ejemplo, cuentas administrativas o técnicas). Esta centrada en accesos remotos con contexto operativo relevante para escenarios de compromiso.   Traducción / contexto: "Inicio de sesión de red sospechoso con cuentas privilegiadas o de servicio". Técnicas MITRE ATT&CK: T1021 (Remote Services) y T1078 (Valid Accounts).
references:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1078/
tags:
  - attack.lateral_movement
  - attack.t1021
  - attack.t1078
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
  filter_builtin_accounts:
    TargetUserName:
      - 'ANONYMOUS LOGON'
      - 'LOCAL SERVICE'
      - 'NETWORK SERVICE'
      - 'SYSTEM'
  filter_machine_accounts:
    TargetUserName|endswith: '$'
  filter_system_sids:
    TargetUserSid:
      - 'S-1-5-18'
      - 'S-1-5-19'
      - 'S-1-5-20'
  filter_local_activity:
    IpAddress:
      - '127.0.0.1'
      - '::1'
      - '-'
  filter_empty_fields:
    WorkstationName: '-'
  filter_common_noise:
    ProcessName:
      - 'C:\Windows\System32\lsass.exe'
  suspicious_account_patterns:
    TargetUserName|re:
      - '(?i).*admin.*'
      - '(?i).*svc.*'
      - '(?i).*service.*'
      - '(?i).*backup.*'
      - '(?i).*sql.*'
      - '(?i).*adm.*'
  condition: selection
             and suspicious_account_patterns
             and not 1 of filter_*
fields:
  - EventID
  - LogonType
  - TargetUserName
  - TargetDomainName
  - IpAddress
  - WorkstationName
  - ProcessName
falsepositives:
  - Cuentas de servicio legítimas utilizadas para acceso a recursos compartidos
  - Tareas administrativas habituales (especialmente en horarios de mantenimiento)
  - Herramientas de gestión IT (backup, despliegue de software, monitorización)
  - Accesos legítimos entre servidores en arquitecturas altamente integradas
level: high
```

2️⃣   
### Inicio de sesión remoto RDP sospechoso (logon tipo 10)
```
</> ATT&CK:  - yaml
title: Suspicious Remote Desktop Logon with Privileged or Non-Standard Account
id: b4e7c8d1-6f2a-4a9b-9c3d-8e5f1a2b7c55
status: experimental
description: Detecta inicios de sesión interactivos remotos mediante RDP (LogonType 10) en sistemas Windows, centrados en cuentas con indicios de privilegio o uso técnico con sesiones remotas potencialmente sensibles. Técnicas MITRE ATT&CK: T1021.001 (Remote Services - Remote Desktop Protocol) y T1078 (Valid Accounts)
references:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
  - https://attack.mitre.org/techniques/T1021/001/
tags:
  - attack.lateral_movement
  - attack.initial_access
  - attack.t1021.001
  - attack.t1078
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 10
  filter_builtin_accounts:
    TargetUserName:
      - 'ANONYMOUS LOGON'
      - 'LOCAL SERVICE'
      - 'NETWORK SERVICE'
      - 'SYSTEM'
  filter_machine_accounts:
    TargetUserName|endswith: '$'
  filter_system_sids:
    TargetUserSid:
      - 'S-1-5-18'
      - 'S-1-5-19'
      - 'S-1-5-20'
  filter_local_ip:
    IpAddress:
      - '127.0.0.1'
      - '::1'
      - '-'
  filter_empty_workstation:
    WorkstationName: '-'
  suspicious_account_patterns:
    TargetUserName|re:
      - '(?i).*admin.*'
      - '(?i).*adm.*'
      - '(?i).*svc.*'
      - '(?i).*backup.*'
      - '(?i).*sql.*'
  condition: selection
             and suspicious_account_patterns
             and not 1 of filter_*
fields:
  - EventID
  - LogonType
```


3️⃣    
### Ejecución sospechosa de PsExec mediante línea de comandos
```
</> ATT&CK: T1021.002 y T1569.002 - yaml
title: Suspicious PsExec Execution via Command Line
id: a7c2e3f4-5b9d-4e2f-8f1c-3d6e9a7b2c11
status: experimental
description: Detecta la ejecución de PsExec o herramientas compatibles a través de la línea de comandos en sistemas Windows, centrándose únicamente en ejecuciones reales del binario o invocaciones desde procesos de usuario, evitando coincidencias genéricas o contextos no ejecutables. Técnicas MITRE ATT&CK: T1021.002 (Remote Services - SMB/Windows Admin Shares) y T1569.002 (System Services - Service Execution)
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
  - https://attack.mitre.org/techniques/T1021/002/
  - https://attack.mitre.org/techniques/T1569/002/
tags:
  - attack.lateral_movement
  - attack.execution
  - attack.t1021.002
  - attack.t1569.002
logsource:
  product: windows
detection:
  selection_process:
    CommandLine|re:
      - '(?i).*\\bpsexec(64)?\\.exe\\b.*'
      - '(?i).*\\bpsexec\\b.+\\\\\\\\.*'   # ejecución remota tipo \\host
  filter_known_paths:
    Image:
      - 'C:\\Windows\\System32\\psexec.exe'
      - 'C:\\Windows\\SysWOW64\\psexec.exe'
  filter_parent_legit_tools:
    ParentImage:
      - 'C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe'
      - 'C:\\Program Files\\Backup\\*'
      - 'C:\\Program Files\\System Center\\*'
  filter_system_accounts:
    User:
      - 'NT AUTHORITY\\SYSTEM'
      - 'NT AUTHORITY\\NETWORK SERVICE'
      - 'NT AUTHORITY\\LOCAL SERVICE'
  condition: selection_process
             and not 1 of filter_*
fields:
  - CommandLine
  - Image
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Uso legítimo de PsExec por administradores de sistemas (especialmente en troubleshooting)
  - Herramientas IT o scripts automatizados que embeben PsExec
  - Soluciones de gestión remota o despliegue que utilicen PsExec internamente
  - Actividades de pentesting autorizadas
level: high
```

4️⃣   
### Ejecución remota sospechosa vía WMI (WMIC)
```
</> ATT&CK: T1047 y T1021 - yaml
title: Suspicious WMI Remote Execution via WMIC Command
id: 3b8f6c1d-2e7a-4a9d-b5c1-9d2e6f7a4c22
status: experimental
description: Detecta el uso de WMIC (Windows Management Instrumentation Command-line) para ejecutar comandos de forma remota. Técnicas MITRE ATT&CK: T1047 (Windows Management Instrumentation) y T1021 (Remote Services).
references:
  - https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic
  - https://attack.mitre.org/techniques/T1047/
tags:
  - attack.lateral_movement
  - attack.execution
  - attack.t1047
  - attack.t1021
logsource:
  product: windows
detection:
  selection_wmic:
    CommandLine|re:
      - '(?i).*wmic.*\\/node:.*process.*call.*create.*'
      - '(?i).*wmic.*\\/node:.*cmd\\.exe.*'
      - '(?i).*wmic.*\\/node:.*powershell.*'
  filter_local_execution:
    CommandLine|re:
      - '(?i).*wmic.*process.*call.*create.*'   # sin /node suele ser local
  filter_system_accounts:
    User:
      - 'NT AUTHORITY\\SYSTEM'
      - 'NT AUTHORITY\\NETWORK SERVICE'
      - 'NT AUTHORITY\\LOCAL SERVICE'
  filter_known_admin_tools:
    ParentImage:
      - 'C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe'
      - 'C:\\Program Files\\System Center\\*'
      - 'C:\\Program Files\\Microsoft Endpoint Manager\\*'
  condition: selection_wmic
             and not filter_local_execution
             and not 1 of filter_*
fields:
  - CommandLine
  - Image
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Herramientas legítimas de administración remota que utilizan WMIC
  - Scripts de administración en entornos legacy
  - Plataformas de gestión (SCCM, monitoring, inventario)
  - Actividad de administradores en tareas de mantenimiento
level: high
```

5️⃣    
### Ejecución remota sospechosa vía WinRM
```
</> ATT&CK:  - yaml
title: Suspicious WinRM Remote Command Execution
id: 6e4d2a1f-9b73-4c5e-8a2f-1c9d7e3b5f44
status: experimental
description: Detecta el uso de WinRM (Windows Remote Management) para ejecutar comandos de forma remota a través de herramientas como PowerShell Remoting o frameworks ofensivos. Se centra en ejecuciones reales mediante línea de comandos (winrm, winrs). Técnicas MITRE ATT&CK: T1021.006 (Remote Services - Windows Remote Management) y T1059.001 (Command and Scripting Interpreter - PowerShell).
references:
  - https://learn.microsoft.com/en-us/windows/win32/winrm/portal
  - https://attack.mitre.org/techniques/T1021/006/
tags:
  - attack.lateral_movement
  - attack.execution
  - attack.t1021.006
  - attack.t1059.001
logsource:
  product: windows
detection:
  selection_winrm_cli:
    CommandLine|re:
      - '(?i).*\\bwinrs\\b.*'
      - '(?i).*\\bwinrm\\b.*invoke.*'
      - '(?i).*\\bwinrm\\b.*create.*'
      - '(?i).*\\bwinrm\\b.*remote.*'
  selection_powershell_remoting:
    CommandLine|re:
      - '(?i).*Invoke-Command.*-ComputerName.*'
      - '(?i).*Enter-PSSession.*-ComputerName.*'
      - '(?i).*New-PSSession.*-ComputerName.*'
  filter_localhost:
    CommandLine|re:
      - '(?i).*localhost.*'
      - '(?i).*127\\.0\\.0\\.1.*'
  filter_system_accounts:
    User:
      - 'NT AUTHORITY\\SYSTEM'
      - 'NT AUTHORITY\\LOCAL SERVICE'
      - 'NT AUTHORITY\\NETWORK SERVICE'
  filter_known_admin_tools:
    ParentImage:
      - 'C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe'
      - 'C:\\Program Files\\System Center\\*'
      - 'C:\\Program Files\\Microsoft Endpoint Manager\\*'
  condition: (selection_winrm_cli or selection_powershell_remoting)
             and not filter_localhost
             and not 1 of filter_*
fields:
  - CommandLine
  - Image
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Administradores utilizando PowerShell Remoting de forma legítima
  - Herramientas de gestión IT (SCCM, Intune, scripts corporativos)
```

6️⃣   
### Enumeración sospechosa de recursos compartidos
```
</> ATT&CK:  T1135, T1069 y T1059 - yaml
title: Suspicious Network Share Enumeration via Net Command
id: 7d3a9c5e-2f1b-4c8d-9e6a-5b2c7f1a8d66
status: experimental
description: Detecta la enumeración de recursos compartidos en sistemas Windows mediante el comando "net share", utilizado para listar los shares disponibles en un equipo. Se utiliza en fases de reconocimiento tras compromiso, para identificar posibles vectores de movimiento lateral. Técnicas MITRE ATT&CK: T1135 (Network Share Discovery), T1069 (Permission Groups Discovery - contexto relacionado) y T1059 (Command and Scripting Interpreter)
references:
  - https://attack.mitre.org/techniques/T1135/
tags:
  - attack.discovery
  - attack.lateral_movement
  - attack.t1135
  - attack.t1059
logsource:
  product: windows
detection:
  selection_net_share:
    CommandLine|re:
      - '(?i).*\\bnet(\\.exe)?\\s+share\\b.*'
      - '(?i).*\\bnet(\\.exe)?\\s+view\\b.*\\\\\\\\.*'   # enumeración remota de shares
  filter_system_accounts:
    User:
      - 'NT AUTHORITY\\SYSTEM'
      - 'NT AUTHORITY\\LOCAL SERVICE'
      - 'NT AUTHORITY\\NETWORK SERVICE'
  filter_machine_accounts:
    User|endswith: '$'
  filter_known_parent_processes:
    ParentImage:
      - 'C:\\Windows\\System32\\services.exe'
      - 'C:\\Windows\\System32\\svchost.exe'
      - 'C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe'
      - 'C:\\Program Files\\System Center\\*'
  filter_scripted_noise:
    CommandLine|contains:
      - 'health'
      - 'monitor'
      - 'inventory'
  condition: selection_net_share
             and not 1 of filter_*
fields:
  - CommandLine
  - Image
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Administradores consultando recursos compartidos manualmente
  - Scripts de inventario o auditoría de red
  - Herramientas de gestión IT o monitorización
  - Actividad legítima en tareas de soporte o troubleshooting
level: medium
```


7️⃣    
### Uso sospechoso de NLTest para reconocimiento de dominio
```
title: Suspicious Domain Discovery via NLTest Command
id: c5a2e1d7-9b4f-4d8c-8e6a-1f3b7a2c9d77
status: experimental
description: Detecta el uso del comando "nltest" en sistemas Windows, herramienta utilizada para obtener información sobre controladores de dominio, confianza entre dominios y estado de autenticación. Se emplea para el reconocimiento en entornos Active Directory usando parámetros típicos (/dclist, /domain_trusts, /dsgetdc, ... ). Técnicas MITRE ATT&CK: T1482 (Domain Trust Discovery), T1018 (Remote System Discovery) y T1059 (Command and Scripting Interpreter).
references:
  - https://attack.mitre.org/techniques/T1482/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nltest
tags:
  - attack.discovery
  - attack.t1482
  - attack.t1018
  - attack.t1059
logsource:
  product: windows
detection:
  selection_nltest:
    CommandLine|re:
      - '(?i).*\\bnltest(\\.exe)?\\b.*\\/dclist.*'
      - '(?i).*\\bnltest(\\.exe)?\\b.*\\/dsgetdc.*'
      - '(?i).*\\bnltest(\\.exe)?\\b.*\\/domain_trusts.*'
      - '(?i).*\\bnltest(\\.exe)?\\b.*\\/trusted_domains.*'
  filter_system_accounts:
    User:
      - 'NT AUTHORITY\\SYSTEM'
      - 'NT AUTHORITY\\LOCAL SERVICE'
      - 'NT AUTHORITY\\NETWORK SERVICE'
  filter_machine_accounts:
    User|endswith: '$'
  filter_known_parent_processes:
    ParentImage:
      - 'C:\\Windows\\System32\\services.exe'
      - 'C:\\Windows\\System32\\lsass.exe'
      - 'C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe'
      - 'C:\\Program Files\\System Center\\*'
  filter_scripted_noise:
    CommandLine|contains:
      - 'health'
      - 'monitor'
      - 'test'
  condition: selection_nltest
             and not 1 of filter_*
fields:
  - CommandLine
  - Image
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Administradores ejecutando consultas de dominio para troubleshooting
  - Scripts de auditoría de Active Directory
  - Herramientas de inventario o monitorización de infraestructura
  - Actividad legítima en controladores de dominio o servidores administrativos
level: high
```


8️⃣    
### Ejecución sospechosa de ipconfig para descubrimiento de red
```
</> ATT&CK:  - yaml
title: Suspicious IPConfig Execution for Network Enumeration
id: 2a7e5c4d-8b1f-4c9a-9d3e-6f2b1a7c5e99
status: experimental
description: Detecta la ejecución del comando "ipconfig" en sistemas Windows, utilizado para obtener información de configuración de red como direcciones IP, puertas de enlace y DNS. Este comando es común en fases de reconocimiento tras compromiso, permitiendo al atacante entender la topología básica de red. Técnicas MITRE ATT&CK: T1016 (System Network Configuration Discovery) y T1059 (Command and Scripting Interpreter).
references:
  - https://attack.mitre.org/techniques/T1016/
tags:
  - attack.discovery
  - attack.t1016
  - attack.t1059
logsource:
  product: windows
detection:
  selection_ipconfig:
    CommandLine|re:
      - '(?i).*\\bipconfig(\\.exe)?\\b.*\\/all.*'
      - '(?i).*\\bipconfig(\\.exe)?\\b.*\\/displaydns.*'
      - '(?i).*\\bipconfig(\\.exe)?\\b.*\\/allcompartments.*'
  filter_system_accounts:
    User:
      - 'NT AUTHORITY\\SYSTEM'
      - 'NT AUTHORITY\\LOCAL SERVICE'
      - 'NT AUTHORITY\\NETWORK SERVICE'
  filter_known_parent_processes:
    ParentImage:
      - 'C:\\Windows\\System32\\services.exe'
      - 'C:\\Windows\\System32\\svchost.exe'
      - 'C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe'
  filter_scripted_noise:
    CommandLine|contains:
      - 'health'
      - 'diagnostic'
      - 'monitor'
  condition: selection_ipconfig
             and not 1 of filter_*
fields:
  - CommandLine
  - Image
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Administradores realizando tareas de troubleshooting de red
  - Scripts de inventario o diagnóstico
  - Herramientas de monitorización
  - Ejecuciones legítimas en soporte técnico
level: medium
```


9️⃣   
### Ejecución sospechosa de netstat para descubrimiento de red
```
</> ATT&CK: T1049 y T1059  - yaml
title: Suspicious Netstat Execution for Network Discovery
id: 9c2a1d7e-4f6b-4d3a-8b1c-5e7f2a9d6c33
status: experimental
description: Detecta la ejecución del comando "netstat" en sistemas Windows, comúnmente utilizado para enumerar conexiones de red activas, puertos abiertos y servicios en escucha. Esta actividad es típica en fases tempranas de reconocimiento tras compromiso, permitiendo al atacante   comprender la exposición de red del sistema. Técnicas MITRE ATT&CK: T1049 (System Network Connections Discovery) y T1059 (Command and Scripting Interpreter).
references:
  - https://attack.mitre.org/techniques/T1049/
tags:
  - attack.discovery
  - attack.t1049
  - attack.t1059
logsource:
  product: windows
detection:
  selection_netstat:
    CommandLine|re:
      - '(?i).*\\bnetstat(\\.exe)?\\b.*-a.*'
      - '(?i).*\\bnetstat(\\.exe)?\\b.*-n.*'
      - '(?i).*\\bnetstat(\\.exe)?\\b.*-o.*'
      - '(?i).*\\bnetstat(\\.exe)?\\b.*-an.*'
      - '(?i).*\\bnetstat(\\.exe)?\\b.*-ano.*'
  filter_system_accounts:
    User:
      - 'NT AUTHORITY\\SYSTEM'
      - 'NT AUTHORITY\\LOCAL SERVICE'
      - 'NT AUTHORITY\\NETWORK SERVICE'
  filter_known_parent_processes:
    ParentImage:
      - 'C:\\Windows\\System32\\services.exe'
      - 'C:\\Windows\\System32\\svchost.exe'
      - 'C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe'
  filter_scripted_noise:
    CommandLine|contains:
      - 'health'
      - 'diagnostic'
      - 'monitor'
  condition: selection_netstat
             and not 1 of filter_*
fields:
  - CommandLine
  - Image
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Administradores ejecutando netstat para troubleshooting
  - Herramientas de monitorización de red o rendimiento
  - Scripts internos de diagnóstico
  - Actividad legítima en servidores (especialmente troubleshooting en caliente)
level: medium
```


1️⃣0️⃣   
### Ejecución sospechosa del comando whoami
```
</> ATT&CK:  T1033 y T1059 - yaml
title: Suspicious Whoami Execution from Command Line
id: e1f3c7b2-8a4d-4c9f-9b2a-7d5e6f1c3a88
status: experimental
description: Detecta la ejecución del comando "whoami" en sistemas Windows, comúnmente utilizado por atacantes para obtener información sobre el contexto de usuario tras comprometer un sistema. Técnicas MITRE ATT&CK: T1033 (System Owner/User Discovery) y T1059 (Command and Scripting Interpreter).
references:
  - https://attack.mitre.org/techniques/T1033/
tags:
  - attack.discovery
  - attack.execution
  - attack.t1033
  - attack.t1059
logsource:
  product: windows
detection:
  selection_whoami:
    CommandLine|re:
      - '(?i).*\\bwhoami(\\.exe)?\\b.*'
      - '(?i).*\\bwhoami\\b.*/all.*'
      - '(?i).*\\bwhoami\\b.*/groups.*'
  filter_system_accounts:
    User:
      - 'NT AUTHORITY\\SYSTEM'
      - 'NT AUTHORITY\\LOCAL SERVICE'
      - 'NT AUTHORITY\\NETWORK SERVICE'
  filter_known_parent_processes:
    ParentImage:
      - 'C:\\Windows\\System32\\services.exe'
      - 'C:\\Windows\\System32\\winlogon.exe'
      - 'C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe'
  filter_scripted_noise:
    CommandLine|contains:
      - 'health'
      - 'diagnostic'
      - 'test'
  condition: selection_whoami
             and not 1 of filter_*
fields:
  - CommandLine
  - Image
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Administradores ejecutando comandos de diagnóstico manual
  - Scripts internos de comprobación de identidad o permisos
  - Herramientas de monitorización o inventario
  - Actividad de troubleshooting
level: medium
```

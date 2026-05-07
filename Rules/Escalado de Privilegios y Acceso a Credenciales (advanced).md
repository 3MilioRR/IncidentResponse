<h1>ESCALADO DE PRIVILEGIOS Y ACCESO A CREDENCIALES (ADVANCED)</h1>

### Privilege Escalation & Credential Access

</>   
Detecta la adición de un usuario a grupos privilegiados de tipo Administrators
```
</> AAT&CK: T1098.007 - yaml
title: User Added to Administrators Group
description: Detecta la adición de un usuario a grupos privilegiados de tipo Administrators (tanto locales como de dominio), lo que podría indicar un intento de escalado de privilegios.
logsource:
  product: windows
  service: security
detection:
  selection_domain:
    EventID: 4728
    TargetUserName|contains: Administrators
  selection_local:
    EventID: 4732
    TargetUserName: Administrators
  filter_machine_accounts:
    SubjectUserName|endswith: '$'
  condition: (selection_domain or selection_local) and not filter_machine_accounts
fields:
  - SubjectUserName
  - TargetUserName
  - MemberName
  - ComputerName
falsepositives:
  - Cambios administrativos legítimos en gestión de usuarios
  - Automatizaciones de provisión (scripts, herramientas IAM)
level: medium
tags:
  - attack.privilege_escalation
  - attack.persistence
  - attack.t1098.007
```

</>   
Detecta la asignación de privilegios especiales (SeDebug, SeTcb, etc.) a cuentas no habituales
```
</> ATT&CK: T1078 - yaml
title: Special Privileges Assigned to Non-Standard Account
description: Detecta la asignación de privilegios especiales (SeDebug, SeTcb, etc.) a cuentas no habituales o no privilegiadas durante el inicio de sesión, lo que podría indicar abuso de credenciales o escalado de privilegios.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4672
  filter_builtin_accounts:
    SubjectUserName:
      - SYSTEM
      - LOCAL SERVICE
      - NETWORK SERVICE
  filter_machine_accounts:
    SubjectUserName|endswith: '$'
  filter_standard_admins:
    SubjectUserName|contains:
      - admin
      - administrador
  condition: selection and not (filter_builtin_accounts or filter_machine_accounts or filter_standard_admins)
fields:
  - SubjectUserName
  - PrivilegeList
  - LogonType
  - ComputerName
falsepositives:
  - Administradores legítimos no incluidos en listas blancas
  - Cuentas de servicio con privilegios elevados
  - Herramientas de gestión remota o automatización
level: low
tags:
  - attack.privilege_escalation
  - attack.credential_access
  - attack.t1078
```

</>   
Detecta el uso de la utilidad RunAs para ejecutar procesos bajo otro contexto de usuario
```
</> ATT&CK: T1548 - yaml
title: Suspicious RunAs Execution by Non-Privileged User
description: Detecta el uso de la utilidad RunAs para ejecutar procesos bajo otro contexto de usuario, especialmente cuando es utilizado por cuentas no privilegiadas, lo que puede indicar intento de escalado de privilegios o abuso de credenciales.
logsource:
  product: windows
detection:
  selection_process:
    Image|endswith: '\runas.exe'
  selection_cmd:
    CommandLine|contains: 'runas'
  filter_machine_accounts:
    User|endswith: '$'
  filter_admin_users:
    User|contains:
      - admin
      - administrador
  condition: (selection_process or selection_cmd) and not (filter_machine_accounts or filter_admin_users)
fields:
  - User
  - CommandLine
  - ParentImage
  - Image
  - ComputerName
falsepositives:
  - Administradores ejecutando RunAs para tareas legítimas
  - Scripts de automatización IT
  - Herramientas de soporte remoto
level: medium
tags:
  - attack.privilege_escalation
  - attack.credential_access
  - attack.t1548
```

</>   
Detecta accesos sospechosos al proceso LSASS, que pueden indicar intentos de volcado de credenciales 
```
</> ATT&CK: T1003- yaml
title: Suspicious Access to LSASS Process
description: Detecta accesos sospechosos al proceso LSASS, que pueden indicar intentos de volcado de credenciales mediante herramientas como Mimikatz o técnicas similares.
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
  suspicious_access:
    GrantedAccess:
      - '0x1010'
      - '0x1410'
      - '0x1fffff'
      - '0x1f0fff'
  filter_legitimate_processes:
    Image|endswith:
      - '\lsass.exe'
      - '\services.exe'
      - '\wininit.exe'
      - '\csrss.exe'
      - '\svchost.exe'
  condition: selection and suspicious_access and not filter_legitimate_processes
fields:
  - Image
  - TargetImage
  - GrantedAccess
  - CallTrace
  - ComputerName
falsepositives:
  - Soluciones EDR/antivirus accediendo a LSASS
  - Herramientas de backup o monitorización con acceso a memoria
  - Software de seguridad legítimo
level: high
tags:
  - attack.credential_access
  - attack.t1003
```

</>   
Detecta el uso de Procdump para volcar la memoria del proceso LSASS
```
</> ATT&CK: T1003 - yaml
title: LSASS Credential Dumping via Procdump
description: Dtitle: LSASS Credential Dumping via Procdump
description: Detecta el uso de Procdump para volcar la memoria del proceso LSASS, lo que puede indicar intento de extracción de credenciales desde el sistema.
logsource:
  product: windows
detection:
  selection_image:
    Image|endswith: '\procdump.exe'
  selection_cmd:
    CommandLine|contains|all:
      - '-ma'
      - 'lsass'
  selection_alt:
    CommandLine|contains:
      - 'lsass.exe'
      - 'lsass'
  filter_legitimate_paths:
    Image|contains:
      - '\Sysinternals\'
  condition: selection_image and (selection_cmd or selection_alt) and not filter_legitimate_paths
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Uso legítimo de Procdump por administradores o equipos de soporte
  - Herramientas internas de diagnóstico
level: high
tags:
  - attack.credential_access
  - attack.t1003.001
```

</>    
Detecta posibles indicadores asociados al uso de Mimikatz u otras herramientas de volcado de credenciales
```
</> ATT&CK: T1003 - yaml
title: Suspicious Mimikatz or Credential Dumping Indicators
description: Detecta posibles indicadores asociados al uso de Mimikatz u otras herramientas de volcado de credenciales, incluyendo comandos relacionados con sekurlsa y cadenas típicas, lo que puede indicar acceso no autorizado a credenciales en memoria.
logsource:
  product: windows
detection:
  selection_cmd:
    CommandLine|contains:
      - 'mimikatz'
      - 'sekurlsa'
      - 'logonpasswords'
      - 'lsadump'
      - 'wdigest'
      - 'kerberos::'
      - 'privilege::debug'
  selection_tools:
    Image|endswith:
      - '\mimikatz.exe'
  suspicious_parents:
    ParentImage|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
  filter_machine_accounts:
    User|endswith: '$'
  condition: (selection_cmd or selection_tools) and suspicious_parents and not filter_machine_accounts
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Pruebas de seguridad o red teaming autorizadas
  - Herramientas de pentesting en entornos controlados
level: high
tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001
```

</>   
Detecta intentos de acceso o volcado del hive SAM del registro de Windows
```
</> ATT&CK: T1003- yaml
title: Suspicious SAM Hive Dumping Activity
description: Detecta intentos de acceso o volcado del hive SAM del registro de Windows mediante herramientas o comandos habituales, lo que puede indicar intento de obtención de credenciales locales.
logsource:
  product: windows
detection:
  selection_reg_save:
    CommandLine|contains|all:
      - 'reg'
      - 'save'
      - 'SAM'
  selection_copy:
    CommandLine|contains|all:
      - 'copy'
      - 'SAM'
  selection_ntdsutil:
    CommandLine|contains|all:
      - 'ntdsutil'
      - 'activate instance'
  selection_esentutl:
    CommandLine|contains|all:
      - 'esentutl'
      - '/y'
      - 'SAM'
  filter_legitimate_paths:
    CommandLine|contains:
      - 'C:\Windows\System32\config\SAM'
  filter_machine_accounts:
    User|endswith: '$'
  condition: (selection_reg_save or selection_copy or selection_ntdsutil or selection_esentutl) 
             and not filter_machine_accounts
fields:
  - Image
  - CommandLine
  - User
  - ParentImage
  - ComputerName
falsepositives:
  - Administradores realizando backups manuales del registro
  - Herramientas de backup legítimas
  - Procesos de recuperación del sistema
level: high
tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.002
```

</>    
Detecta el uso de herramientas y comandos comunes para realizar volcados de memoria del proceso LSASS
```
</> ATT&CK: T1003 - yaml
title: Suspicious LSASS Memory Dump via Command Line Tools
description: Detecta el uso de herramientas y comandos comunes para realizar volcados de memoria del proceso LSASS, lo que puede indicar intento de robo de credenciales en el sistema.
logsource:
  product: windows
detection:
  selection_procdump:
    CommandLine|contains|all:
      - 'procdump'
      - 'lsass'
  selection_rundll32:
    CommandLine|contains|all:
      - 'rundll32'
      - 'comsvcs.dll'
      - 'MiniDump'
  selection_taskmgr:
    CommandLine|contains|all:
      - 'taskmgr'
      - 'lsass'
  selection_powershell:
    CommandLine|contains|all:
      - 'powershell'
      - 'lsass'
  filter_machine_accounts:
    User|endswith: '$'
  condition: (selection_procdump or selection_rundll32 or selection_taskmgr or selection_powershell)
             and not filter_machine_accounts
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Actividades legítimas de troubleshooting o debugging
  - Uso de herramientas de administración por equipos IT
  - Soluciones EDR realizando análisis de memoria
level: high
tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001
```

</>    
Detecta el uso de privilegios sensibles asociados a la manipulación de tokens o elevación de privilegios
```
</> ATT&CK: T1134 - yaml
title: Suspicious Sensitive Privilege Use (Token Manipulation)
description: Detecta el uso de privilegios sensibles asociados a la manipulación de tokens o elevación de privilegios (como SeDebugPrivilege o SeImpersonatePrivilege) por cuentas no habituales, lo que puede indicar intento de escalado de privilegios o abuso de credenciales.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4673
  sensitive_privileges:
    PrivilegeList|contains:
      - SeDebugPrivilege
      - SeImpersonatePrivilege
      - SeAssignPrimaryTokenPrivilege
      - SeTcbPrivilege
  filter_builtin_accounts:
    SubjectUserName:
      - SYSTEM
      - LOCAL SERVICE
      - NETWORK SERVICE
  filter_machine_accounts:
    SubjectUserName|endswith: '$'
  filter_legitimate_processes:
    ProcessName|endswith:
      - '\lsass.exe'
      - '\services.exe'
      - '\wininit.exe'
      - '\svchost.exe'
  condition: selection and sensitive_privileges and not (filter_builtin_accounts or filter_machine_accounts or filter_legitimate_processes)
fields:
  - SubjectUserName
  - ProcessName
  - PrivilegeList
  - ComputerName
falsepositives:
  - Procesos administrativos legítimos
  - Herramientas de gestión IT
  - Software de seguridad (EDR/AV)
level: medium
tags:
  - attack.privilege_escalation
  - attack.credential_access
  - attack.t1134
```

</>    
Detecta la enumeración de grupos privilegiados mediante comandos
```
</> ATT&CK: T1069 - yaml
title: Suspicious Enumeration of Privileged Groups
description: Detecta la enumeración de grupos privilegiados mediante comandos como "net group" o "net localgroup", especialmente cuando se enfocan en grupos administrativos, lo que puede indicar reconocimiento previo a un escalado de privilegios.
logsource:
  product: windows
detection:
  selection_domain:
    CommandLine|contains|all:
      - 'net group'
      - 'admin'
  selection_local:
    CommandLine|contains|all:
      - 'net localgroup'
      - 'Administrators'
  selection_sensitive_groups:
    CommandLine|contains:
      - 'Domain Admins'
      - 'Enterprise Admins'
      - 'Administrators'
      - 'Remote Desktop Users'
  suspicious_parents:
    ParentImage|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
  filter_machine_accounts:
    User|endswith: '$'
  filter_admin_users:
    User|contains:
      - admin
      - administrador
  condition: (selection_domain or selection_local or selection_sensitive_groups)
             and suspicious_parents
             and not (filter_machine_accounts or filter_admin_users)
fields:
  - User
  - CommandLine
  - ParentImage
  - ComputerName
falsepositives:
  - Administradores realizando tareas de gestión
  - Scripts de inventario o auditoría
  - Herramientas IT legítimas
level: low
tags:
  - attack.discovery
  - attack.t1069
  - attack.t1069.001
  - attack.t1069.002
```


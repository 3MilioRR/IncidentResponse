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


```
</> ATT&CK: - yaml
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
</> ATT&CK: - yaml
title: SAM Hive Access
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "SAM"
  condition: selection
```

```
</> ATT&CK: - yaml
title: LSASS Memory Dump
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "lsass"
  condition: selection
```

```
</> ATT&CK: - yaml
title: Suspicious Token Manipulation
logsource: {product: windows}
detection:
  selection:
    EventID: 4673
  condition: selection
```

```
</> ATT&CK: - yaml
title: Privileged Group Enumeration
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "net group"
  condition: selection
```


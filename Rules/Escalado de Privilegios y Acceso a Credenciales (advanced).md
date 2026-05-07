<h1>ESCALADO DE PRIVILEGIOS Y ACCESO A CREDENCIALES (ADVANCED)</h1>

### Privilege Escalation & Credential Access

</>   
Detecta la adición de un usuario a grupos privilegiados de tipo Administrators
```
</> yaml
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

```
</> yaml
title: Special Privileges Assigned
logsource: {product: windows}
detection:
  selection:
    EventID: 4672
  condition: selection
```

```
</> yaml
title: RunAs Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "runas"
  condition: selection
```

```
</> yaml
title: LSASS Access
logsource: {product: windows}
detection:
  selection:
    TargetImage|endswith: lsass.exe
  condition: selection
```

```
</> yaml
title: Credential Dump via Procdump
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "procdump"
  condition: selection
```

```
</> yaml
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
</> yaml
title: SAM Hive Access
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "SAM"
  condition: selection
```

```
</> yaml
title: LSASS Memory Dump
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "lsass"
  condition: selection
```

```
</> yaml
title: Suspicious Token Manipulation
logsource: {product: windows}
detection:
  selection:
    EventID: 4673
  condition: selection
```

```
</> yaml
title: Privileged Group Enumeration
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "net group"
  condition: selection
```


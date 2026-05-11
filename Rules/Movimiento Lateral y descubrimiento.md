<H1>LATERAL MOVEMENT & DISCOVERY</H1>
### Lateral Movement & Discovery

1
2
3
4
5
6
7
8
9
10


1️⃣   
</> Inicio de sesión de red sospechoso con cuentas privilegiadas o de servicio (logon tipo 3)
```
</> ATT&CK: T1021 y T1078 - yaml
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
</> 
```
</> ATT&CK:  - yaml
title: PsExec Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "psexec"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: WMI Remote Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "wmic"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: WinRM Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "winrm"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: RDP Logon
logsource: {product: windows}
detection:
  selection:
    EventID: 4624
    LogonType: 10
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Whoami Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "whoami"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Netstat Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "netstat"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: IPConfig Execution
logsource: {product: windows}
detection:
  selection
    CommandLine|contains: "ipconfig"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: NLTest Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "nltest"
  condition: selection
```

```
</> ATT&CK:  - yaml
title: Share Enumeration
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "net share"
  condition: selection
```

<h1>ESCALADO DE PRIVILEGIOS Y ACCESO A CREDENCIALES (ADVANCED)</h1>

### Privilege Escalation & Credential Access

```
</> yaml
title: User Added to Administrators
logsource: {product: windows}
detection:
  selection:
    EventID: 4728
  condition: selection
```

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


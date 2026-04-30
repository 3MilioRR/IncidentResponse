<H1>LATERAL MOVEMENT & DISCOVERY</H1>
### Lateral Movement & Discovery

```
</> yaml
title: Network Logon
logsource: {product: windows}
detection:
  selection:
    EventID: 4624
    LogonType: 3
  condition: selection
```

```
</> yaml
title: PsExec Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "psexec"
  condition: selection
```

```
</> yaml
title: WMI Remote Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "wmic"
  condition: selection
```

```
</> yaml
title: WinRM Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "winrm"
  condition: selection
```

```
</> yaml
title: RDP Logon
logsource: {product: windows}
detection:
  selection:
    EventID: 4624
    LogonType: 10
  condition: selection
```

```
</> yaml
title: Whoami Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "whoami"
  condition: selection
```

```
</> yaml
title: Netstat Execution
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "netstat"
  condition: selection
```

```
</> yaml
title: IPConfig Execution
logsource: {product: windows}
detection:
  selection
    CommandLine|contains: "ipconfig"
  condition: selection
```

```
</> yaml
title: NLTest Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "nltest"
  condition: selection
```

```
</> yaml
title: Share Enumeration
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "net share"
  condition: selection
```

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

¿que indica esté pseudo-código? Traducción: Si alguien usa PowerShell para descargar cosas → sospechoso

Pero esta regla es solo un ejemplo. Es demasiado sencilla y si la pones en producción generará mucho ruido pero poca utilidad.

A continuación tienes un set de ***50 reglas Sigma*** listas para usar como base. Las tienes en versión 'basic' (simplificadas pero funcionales) y versión 'advanced' (optimizadas para usar).


## 50 reglas sigma
He repartido las reglas en diferentes categorías atendiendo a los siguientes temas:

- :clipboard: [Power Shell Execution](#powershell--execution)
- :anchor: [Persistence](Rules/Persistencia.md)
- :ticket: [Privilege Escalation & Credential Access](Rules/Escalado%20de%20Privilegios%20y%20Acceso%20a%20Credenciales.md)
- :ladder: [Lateral Movement & Discovery](Rules/Movimiento%20Lateral%20y%20descubrimiento.md)
- :goal_net: Exfiltracion e Impacto [(Basic)](Rules/Exfiltracion%20e%20Impacto.md)

⚠️ Están optimizadas para claridad y uso práctico. Aunque cubren muchas casuísticas, no esperes que cubran el 100% de tus necesidades. Úsalas como una base de partida.


## Importante

Cada regla está asociada a una (o varias) técnicas de MITRE. La idea es que consultes la técnica que quieras cubrir y averigües qué data source y/o que log registra la actividad que te permita investigar si has recibido ese ataque. De nada sirve la regla si el log no está activo o no se registra actividad.

Recuerda que SIGMA es agnostica de tus herramientas. Describe el comportamiento del atacante, pero no la implementación específica en un determinado SIEM.



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


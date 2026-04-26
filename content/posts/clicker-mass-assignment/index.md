---
title: "De jugador a admin con un salto de linea"
date: 2026-04-18
description: "Como Mass Assignment y un filtro penoso me dieron admin en una app de Hack The Box. Spoiler: el developer confio en un denylist."
tags: ["HTB", "Clicker", "Mass Assignment", "Newline Injection", "Parameter Smuggling", "PHP", "CWE-915"]
categories: ["Writeups"]
toc: true
draft: false
---

![Clicker has been Pwned](clicker_pwned.png)

{{< boxinfo name="Clicker" os="Linux" difficulty="Medium" points="30" date="18 Apr 2026" url="https://app.hackthebox.com/machines/Clicker" tags="Mass Assignment, Newline Injection, Parameter Smuggling, PHP, NFS, Source Code Review" >}}

Llevaba un rato mirando la ficha de **Clicker** en Hack The Box. Maquina medium, web, PHP, Linux. De esas que miras y piensas "esto lo saco en una hora con un cafe". Spoiler: no fue una hora. Pero lo que encontre dentro merece un post, porque el fallo de fondo es tan tonto, tan comun, y tan facil de explotar que da rabia que siga apareciendo en 2026. Y no solo en CTFs. En produccion. En aplicaciones reales. En sitios donde hay dinero de por medio.

La app resulta ser un juego de clicker. Si, un juego de hacer clicks. De esos que te enganchan media hora y luego te preguntas que estas haciendo con tu vida. Tienes tu perfil de jugador, haces clicks, subes de nivel, y cuando le das a "Save and close" tus datos se mandan al servidor en una peticion GET. Sencillo.

Pero lo interesante no es el juego. Lo interesante es lo que hay debajo. Porque durante la enumeracion, monte el recurso **NFS** que tenia la maquina expuesto y saque un backup con todo el codigo fuente de la aplicacion. Y cuando digo todo, digo *todo*: `admin.php`, `save_game.php`, `db_utils.php`, `export.php`... El developer nos habia dejado las llaves puestas en el coche.

# Abriendo el capo: el codigo fuente

Lo primero que hice fue un `tree` para ver la estructura de archivos. La app es PHP clasico, sin framework, con Bootstrap en el front y una base de datos MySQL detras. Los archivos que me llamaron la atencion fueron estos:

- `save_game.php`: guarda tu partida (clicks y level)
- `db_utils.php`: funciones de acceso a la base de datos
- `admin.php`: panel de administracion (protegido por sesion)
- `export.php`: exporta datos de jugadores (solo admin)

Lo primero que me miro siempre en una app PHP es como interactua con la base de datos. Asi que abro `db_utils.php` y empiezo a leer funciones.

La funcion `create_new_player` me revela la estructura de la tabla `players`:

```php
$stmt = $pdo->prepare("INSERT INTO players(username, nickname, password, role, clicks, level) VALUES (:username, :nickname, :password, :role, :clicks, :level)");
```

Ahi tenemos las columnas: `username`, `nickname`, `password`, `role`, `clicks` y `level`. La columna `role` es la que define si eres `User` o `Admin`. Y el objetivo de toda esta historia es cambiar ese valor sin que nadie nos invite.

La funcion `load_profile` confirma que la app carga el `role` del usuario desde la base de datos:

```php
function load_profile($player) {
    global $pdo;
    $params = ["player"=>$player];
    $stmt = $pdo->prepare("SELECT nickname, role, clicks, level FROM players WHERE username = :player");
    $stmt->execute($params);
    if ($stmt->rowCount() > 0) {
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row;
    }
    return array();
}
```

Y `get_top_players` es una funcion reservada para el admin:

```php
// ONLY FOR THE ADMIN
function get_top_players($number) {
    global $pdo;
    $stmt = $pdo->query("SELECT nickname,clicks,level FROM players WHERE clicks >= " . $number);
    $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return $result;
}
```

Hasta aqui todo mas o menos normal. Pero la cosa se pone interesante cuando miro como se guardan los datos.

## save_game.php: aqui empieza la fiesta

Este es el archivo que se ejecuta cuando guardas tu partida. El completo:

```php
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
    $args = [];
    foreach($_GET as $key=>$value) {
        if (strtolower($key) === 'role') {
            // prevent malicious users to modify role
            header('Location: /index.php?err=Malicious activity detected!');
            die;
        }
        $args[$key] = $value;
    }
    save_profile($_SESSION['PLAYER'], $_GET);
    // update session info
    $_SESSION['CLICKS'] = $_GET['clicks'];
    $_SESSION['LEVEL'] = $_GET['level'];
    header('Location: /index.php?msg=Game has been saved!');
}
?>
```

A ver si lo desgranamos. El codigo recorre *todos* los parametros que le llegan por GET y los mete en un array. Todos. Sin excepcion. Lo unico que hace es comprobar que el nombre del parametro no sea exactamente `role` (incluso el comentario del developer dice "prevent malicious users to modify role", o sea que el tio *sabia* que esto era un problema). Si detecta `role`, te suelta un "Malicious activity detected!" y te echa. Todo lo demas, bienvenido sea. Y luego se lo pasa enterito a `save_profile()`.

## save_profile(): donde se materializa el desastre

Esta es la funcion en `db_utils.php` que recibe los parametros y construye la query:

```php
function save_profile($player, $args) {
    global $pdo;
    $params = ["player"=>$player];
    $setStr = "";
    foreach ($args as $key => $value) {
        $setStr .= $key . "=" . $pdo->quote($value) . ",";
    }
    $setStr = rtrim($setStr, ",");
    $stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");
    $stmt -> execute($params);
}
```

Miradla bien. La funcion construye la clausula `SET` de la query SQL *dinamicamente* con todo lo que le pases. El nombre del parametro GET se convierte directamente en el nombre de la columna SQL. Sin allowlist de campos. Sin validacion de nombres de columna. Sin nada. El developer usa `$pdo->quote()` para escapar los *valores* (bien), pero los *nombres de las columnas* vienen directamente del input del usuario (fatal).

Si el juego manda `clicks=100&level=5`, genera `UPDATE players SET clicks='100', level='5' WHERE username = :player`. Perfecto. Pero si tu mandas `clicks=100&level=5&role=Admin`... pues genera `UPDATE players SET clicks='100', level='5', role='Admin' WHERE username = :player`. Asi, sin despeinarse.

Esto tiene un nombre: **Mass Assignment**. Y si no te suena o lo has visto de pasada sin darle importancia, quedate, porque es de esas vulnerabilidades que te encuentras constantemente en engagements reales.

# Un momento, que es Mass Assignment?

## La version simple

Imagina que vas a un restaurante. El camarero te trae un formulario de pedido con dos campos: primer plato y segundo plato. Tu lo rellenas, pero ademas escribes a mano un tercer campo: "propina: -50 euros". Si el restaurante procesa *todo* lo que hay en el papel sin comprobar que campos son suyos y cuales te has inventado tu, te acaban debiendo dinero. Brillante.

Con **Mass Assignment** pasa exactamente lo mismo. El formulario de la web muestra dos campos (`clicks` y `level`), pero tu anades uno mas en la URL (`role=Admin`), y el servidor lo acepta porque nadie le ha ensenado a distinguir entre lo legitimo y lo que te has sacado de la manga.

## La version tecnica

El problema de fondo es que el developer, por vago (no hay otra forma de decirlo), escribe algo tipo `$user->update($_POST)` en vez de definir explicitamente que campos acepta. Menos codigo, mas rapido, funciona. Hasta que alguien con dos dedos de frente anade parametros extra que no estaban en el formulario. Y el backend los acepta encantado.

Y no creas que esto es cosa solo de PHP cutre. Todos los stacks tienen su version del mismo error:

- En **Django**, un `ModelForm` sin definir `fields` expone todos los campos del modelo.
- En **Rails** antes de la version 4, todos los atributos eran asignables por defecto. Literalmente todos.
- En **Laravel**, un modelo Eloquent con `$guarded = []` es una invitacion abierta.
- En **Node con MongoDB**, el clasico `User.findByIdAndUpdate(id, req.body)` acepta lo que le eches.
- En cualquier **API REST** que haga un `PATCH` sin validar los campos del body JSON.

De hecho, el momento en que todo el mundo se entero de que esto era un problema serio fue en 2012, cuando Egor Homakov exploto exactamente esto en **GitHub**. Si, en GitHub. Se dio acceso de commit al repositorio del framework Rails anadiendo su clave SSH publica a traves de un campo que no deberia haber sido modificable. GitHub tuvo que parchear su plataforma de urgencia, Rails introdujo `strong_parameters` como respuesta directa, y el mundo aprendio (o deberia haber aprendido) que dejar que el usuario te diga que campos quiere modificar es una idea pesima. Y aun asi, aqui estamos, encontrandonos lo mismo en 2026.

## Mass Assignment vs IDOR

Se confunden mucho y son primas pero no hermanas. Merece la pena tener clara la diferencia:

- **Mass Assignment**: modificas *campos que no deberias poder tocar* en tu propio recurso. Tu perfil, tus datos, pero cambias el `role` o el `is_admin` o los `credits`.
- **IDOR**: accedes al *recurso de otro usuario* cambiando un identificador. Tu eres el user 42 pero miras los datos del user 1337.

Son vulnerabilidades distintas con vectores distintos. Pero si combinas las dos, puedes modificar campos protegidos de otros usuarios. Eso ya es game over total.

# Volviendo a Clicker: el guardia y como enganarlo

Ya tenemos claro que hay **Mass Assignment**. El vector obvio seria meter `&role=Admin` en la URL y ver que pasa. Pero el developer no era *completamente* tonto. Recordemos el filtro:

```php
foreach($_GET as $key=>$value) {
    if (strtolower($key) === 'role') {
        // prevent malicious users to modify role
        header('Location: /index.php?err=Malicious activity detected!');
        die;
    }
    $args[$key] = $value;
}
```

Si el parametro se llama `role`, te bloquea. Da igual que lo pongas en mayusculas, minusculas o mezcla, porque usa `strtolower()`. La comparacion es estricta con `===`. Primer intento al traste.

Pero aqui me quede un rato pensando. El filtro compara strings. Si la string no es *exactamente* `"role"`, pasa. Entonces la pregunta se hace sola: que pasa si le meto un caracter que PHP vea como parte del nombre del parametro pero que MySQL ignore a la hora de ejecutar la query?

## Bypass 1: Newline Injection (%0a)

Piensalo como un guardia de discoteca con una lista negra que tiene un solo nombre: "Pepe". Si le dices "soy Pepe", no entras. Pero si le dices "soy Pepe\n" (con un salto de linea invisible al final), el guardia compara "Pepe\n" con "Pepe", ve que no son iguales, y te deja pasar. Tu sigues siendo Pepe, obviamente, pero el guardia es tan literal que no se da cuenta.

`%0a` es un newline codificado en URL. El caracter que se genera cuando pulsas Enter. Invisible pero esta ahi. Si en vez de `role=Admin` mando `role%0a=Admin`, PHP recibe como nombre de parametro la string `"role\n"`. La request queda asi:

```
GET /save_game.php?clicks=4&level=0&role%0a=Admin HTTP/1.1
Host: clicker.htb
```

El filtro hace `strtolower("role\n") === "role"`, resultado `false`, y deja pasar. El parametro entra en `$args` y se lo pasa a `save_profile()`.

Cuando `save_profile()` concatena ese nombre de parametro en la clausula `SET`, genera esta query:

```sql
UPDATE players SET clicks='4', level='0', role
='Admin' WHERE username = 'deadlock';
```

Ese salto de linea entre `role` y `=` para MySQL es whitespace. Le da absolutamente igual. La query es valida y se ejecuta sin problema. Role actualizado a `Admin`.

La respuesta del servidor lo confirma: `HTTP/1.1 302 Found` con `Location: /index.php?msg=Game has been saved!`. Ni un error. Ni una queja. Guardadito.

El mismo caracter, dos interpretaciones completamente distintas. PHP lo ve como parte del nombre y falla la comparacion. MySQL lo ve como ruido y lo ignora. Esa discrepancia entre capas es lo que hace posible el bypass.

## Bypass 2: Parameter Smuggling con %3d

Este fue el que mas me gusto, y el que me hizo pensar "esto es elegante de narices".

`%3d` es el signo `=` codificado en URL. La idea es meterlo dentro del nombre del parametro para hacer smuggling de la asignacion SQL completa. Suena raro, pero mira la request:

```
GET /save_game.php?role%3d'Admin',clicks=4&level=0 HTTP/1.1
Host: clicker.htb
```

La clave esta en como PHP parsea la query string. Lo hace en dos pasos. Primero separa por `&`, asi que obtiene `role%3d'Admin',clicks=4` y `level=0`. Luego busca el primer `=` **literal** (no el `%3d`, que esta codificado) para dividir cada trozo en clave y valor.

Asi que PHP acaba viendo dos parametros:

- Clave: `role='Admin',clicks` con valor `4`
- Clave: `level` con valor `0`

El filtro comprueba `strtolower("role='Admin',clicks") === "role"`. Ni de lejos. Pasa sin problema.

Y cuando `save_profile()` construye el SQL usando esa clave como si fuera un nombre de columna:

```sql
UPDATE players SET role='Admin',clicks='4', level='0' WHERE username='deadlock';
```

SQL perfectamente valido. Lo que para PHP era el *nombre del parametro* se convierte en *dos asignaciones validas* dentro del `SET`. El servidor responde con un `302 Found` y un `msg=Game has been saved!`. Gracias, buen hombre.

La diferencia fundamental con el newline es que aqui no estas inyectando whitespace que MySQL ignora. Estas aprovechando que HTTP y SQL interpretan el `=` de forma completamente distinta. Para HTTP es un separador clave-valor (pero solo el literal, no el codificado). Para SQL es un operador de asignacion. Dos mundos parseando la misma string con reglas distintas.

## El resto de vectores

Una vez que entiendes el principio, te das cuenta de que el filtro es un colador. Cualquier caracter que MySQL trate como whitespace pero que rompa la comparacion exacta en PHP vale como bypass.

El carriage return funciona igual que el newline:

```
GET /save_game.php?clicks=4&level=0&role%0d=Admin HTTP/1.1
Host: clicker.htb
```

PHP recibe `"role\r"`, el filtro no matchea, y MySQL lo trata como whitespace. Mismo resultado.

El tab tambien:

```
GET /save_game.php?clicks=4&level=0&role%09=Admin HTTP/1.1
Host: clicker.htb
```

Y luego esta la via del comentario SQL, que es conceptualmente distinta:

```
GET /save_game.php?clicks=4&level=0&role/**/=Admin HTTP/1.1
Host: clicker.htb
```

PHP recibe `"role/**/"` como nombre de parametro. El filtro no lo reconoce como `"role"`. Y cuando llega a MySQL, el parser elimina el comentario vacio `/**/` y queda `role = 'Admin'`. Limpio.

En resumen, estos son todos los vectores que funcionan:

- `role%0a` (newline), `role%0d` (carriage return), `role%09` (tab), `role%20` (espacio): whitespace que MySQL ignora y PHP incluye en la comparacion.
- `role/**/`: comentario SQL vacio que MySQL elimina y PHP trata como parte del nombre.
- `role%3d'Admin',clicks`: smuggling de la asignacion completa dentro del nombre del parametro HTTP.

Seis formas de bypassear un filtro de una linea. Y probablemente hay mas. El problema de fondo no es el caracter concreto que uses, sino que el filtro opera en una capa y la query se ejecuta en otra con reglas distintas.

# El detalle de la sesion

Despues del bypass, me fui directo a `/admin.php` esperando ver el panel de administracion y... nada. Redireccion al index. Que pasa?

El `role` en la base de datos ya era `Admin`, pero `$_SESSION['ROLE']` seguia siendo `User`. Y claro, tiene sentido si miras el codigo. La sesion de PHP se carga con los datos del usuario en el momento del login, no se refresca en cada request. El check de `admin.php` comprueba la sesion, no la base de datos:

```php
if ($_SESSION["ROLE"] != "Admin") {
    header('Location: /index.php');
    die;
}
```

Asi que hice logout, volvi a iniciar sesion, y ahi estaba: el panel de administracion con la tabla de top players y la funcionalidad de exportar datos. Un detalle tonto que en un CTF te puede hacer perder media hora maldiciendo al monitor si no paras a pensarlo.

## Que hay en el panel de admin?

El panel muestra los top players (los que superan un threshold de clicks) y ofrece exportar esos datos en tres formatos: `txt`, `json` y `html`. El archivo `export.php` es interesante porque genera un archivo en el servidor con un nombre aleatorio y la extension que tu elijas:

```php
$filename = "exports/top_players_" . random_string(8) . "." . $_POST["extension"];
file_put_contents($filename, $s);
header('Location: /admin.php?msg=Data has been saved in ' . $filename);
```

Esa extension que viene directamente del POST del usuario sin validar... pero eso ya es otra historia y otro vector de ataque. Por ahora nos quedamos con que hemos conseguido admin a traves de **Mass Assignment**.

# Lo que me llevo de esta maquina

El patron de fondo de esta maquina es algo que me encuentro constantemente, tanto en CTFs como en engagements reales, y merece la pena desgranarlo bien.

La raiz tecnica del problema es que el codigo construye la query SQL concatenando directamente las claves del input del usuario. No los valores (esos estan escapados con `$pdo->quote()`), sino las *claves*. Eso significa que cualquier caracter que metas en el nombre del parametro acaba *dentro de la estructura de la query*. No en un valor entrecomillado y escapado. En la estructura. En el `SET`. El usuario controla parte de la sintaxis SQL, y eso ya es un problema gordo independientemente de que haya filtro o no.

El filtro intenta parchear eso bloqueando un nombre concreto (`role`), pero esta atacando el sintoma en vez de la causa. Es como poner un cartel de "prohibido entrar" en una puerta que no tiene cerradura. El cartel solo funciona con la gente que lo lee y decide obedecerlo. Nosotros no somos esa gente.

Lo que deberia haber hecho el developer es una **allowlist** de campos aceptados:

```php
$allowed = ['clicks', 'level'];
$args    = [];

foreach ($allowed as $field) {
    if (isset($_GET[$field])) {
        $args[$field] = $_GET[$field];
    }
}

save_profile($_SESSION['PLAYER'], $args);
```

Con esto da igual que mandes `role`, `role%0a`, `role%3d'Admin',clicks` o lo que te de la gana. Si el campo no esta en `$allowed`, se ignora. Pero claro, eso requiere pensar un momento en que campos son legitimos, y ahi es donde la pereza del developer se convierte en tu vector de entrada.

Lo que hace posible los bypasses es la **discrepancia entre capas del stack**. PHP parsea la query string con unas reglas. MySQL parsea el SQL con otras. Los caracteres que son significativos en una capa son ruido en la otra, y viceversa. Y esa frontera entre tecnologias es exactamente donde se abren los huecos.

Esto es un principio general que aplica mucho mas alla de esta maquina:

- Filtro en la aplicacion, ejecucion en la base de datos: piensa en que trata MySQL como whitespace o como sintaxis valida.
- Filtro en un WAF, procesamiento en el backend: piensa en encoding, double encoding, normalizacion de caracteres.
- Validacion en el frontend, logica en el servidor: piensa en que asunciones hace cada capa sobre el formato de los datos.

La pregunta que te tienes que hacer siempre es la misma: **que pasa si lo que yo mando se interpreta de forma distinta en cada capa que lo procesa?** Si el filtro ve una cosa y el consumidor final ve otra, tienes un vector. Solo necesitas encontrar el caracter o la codificacion que explota esa diferencia.

En el caso de Clicker, el developer vio el problema (Mass Assignment del campo `role`) e intento arreglarlo con un denylist de un solo caso. Un parche que cubre el ataque mas obvio pero que se desmorona en cuanto te sales un milimetro del caso esperado. Seis bypasses distintos con un filtro de una linea. Imaginate lo que pasa con filtros mas complejos que dan una falsa sensacion de seguridad.

> **Lo que me llevo:** Cuando veas un filtro por nombre de parametro, no pienses en como se llama el campo. Piensa en como lo interpreta cada capa del stack. El bypass esta en la discrepancia entre lo que el filtro ve y lo que la base de datos ejecuta. Siempre.

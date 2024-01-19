# wolRepeater

Un simple script clonado de <https://github.com/jaime29010/wol-packet-replicator> y un poco modificado.

Esta es una forma fàcil de usar un WakeOnLan desde fuera de la red _cuando tu router no soporta el reenvio de paquetes_ a la direccion de broadcast

El script tambien soporta la feature SecureOn si la NIC no la soporta

## Dependencias

Para crear un entono virtual de python necesitamos los paquetes

- python3-venv  : para crear el entorno virtuak
- python3-dev   : para construir las dependencias dentro del entorno virtual
  
Para ejecutar el script necesitamos la dependencia

- jsonschema    : para checkear el fichero json de la configuracion

## instalación/configuración

La configuracioón se puede realizar con cualquier usuario que tenga permisos para escribir en el directorio de destino.

La ejecución tambien se puede realizar por cualquier usuario.

Direcciones del repositorio:

- https : https://github.com/uab-dtic/wolRepeater.git
- ssh   : git@github.com:uab-dtic/wolRepeater.git

**Vamos a suponer que tenemos el codigo en el directorio /opt/wolRepeater.**

Si descargamos desde un repositorio de git lo podemos hacer directamente con el comando

```bash
git clone {REPOSITORY} /opt/wolRepeater
```

Creamos el entorno virtual

```bash
cd /opt/wolrepeater
python -m venv env
. env/bin/activate
```

En este punto en el prompt debemos ver que estamos en un entorno virtual

```data
(env) root@hostname:/opt/wolRepeater #
```

Añadimos las dependencias

```bash
(env) root:/opt/wolRepeater # pip install -r requirements.txt
```

## Forma de uso desde linea de comandos

Si necesitamos que el entorno virtual quede persistente necesitamos activarlo

```bash
usuario@localhost:~$ cd /opt/wolRepeater
usuario@localhost:/opt/wolRepeater$ . env/bin/activate
(env) usuario@localhost:/opt/wolRepeater$ ./wolRepeater -h
...
```

Si queremos ejecutarlo **sin un entorno virtual persistente**

```bash

usuario@localhost:~ # /opt/wolRepeater/env/bin/python /opt/wolRepeater/wolReperater.py -h
...

```

## Opciones de uso

```bash
./wolRepeater.py [-h] [-i ip] [-p port] [-t ip] [-r port] [-s password] [-z password] [-f mac_and_passwd_json_file] [-l log file]

   -h show this help.
   -i binding ip. Default 0.0.0.0.
   -p binding port. Default 5009.
   -t target ip. Default 255.255.255.255.
   -r target port. Default 9.
   -f json file with mac\'s and passwords for SecureOn. View format down.
   -s password for use on forward packet with SecureOn. Default ''.
   -z password to check on received packets with SecureOn. Default ''.
   -l file log
   -v LOGLEVEL


Formato del fichero json

[
  { "ethernet": "112233445566", "password": "aabbccddeeff",
  { "ethernet": "aa2233445566", "password": "11bbccddeeff"  
]

Environment Variables:
   LOGLEVEL=[DEBUG|INFO|WARNING|ERROR|CRITICAL] default=INFO

Examples:

```data
     ./wolRepeater.py -h
     ./wolRepeater.py -i 192.168.1.100
     ./wolRepeater.py -p 8000
     ./wolRepeater.py -t 192.168.1.100
     ./wolRepeater.py -r 8000
     ./wolRepeater.py -s 112233445566
     ./wolRepeater.py -f /etc/wol/mac_and_pass.json
     ./wolRepeater.py -z aabbccddeeff
     ./wolRepeater.py -l /var/log/wol_wolRepeater.log
     LOGLEVEL=DEBUG ./replicator.py
```

## Forma de uso desde SystemD

Copiar o hacer un link del fichero wolRepeater.service a /etc/systemd/system/

```bash
sudo ln -s /opt/wolRepeater/wolRepeater.service /etc/systemd/system/wolRepeater.service
```
el servicio se arrancará con el usuario wolrepeater que debemos crear

```bash
sudo adduser --system --no-create-home --home /opt/wolrepeater --shell /usr/sbin/nologin wolrepeater
```

Modificar el fichero **/opt/wolRepeater/wolRepeater.conf** con las opciones apropiadas

***OJO!!!** si se usa la opcion -l para generar un fichero de log en /var/log/wolRepeater.log, este fichero **DEBE** ser propiedad del usuario que arranca el servicio (_wolrepeater_)

```bash
sudo touch /var/log/wolRepeater.log
sudo chown wolrepeater /var/log/wolRepeater.log
```

Habilitar el servicio para que arranque tras un reinicio

```bash
sudo systemctl enable wolRepeater
```

Arrancar el servicio manualmente

```bash
sudo systemctl start wolRepeater
```

Comprobar el estadodel servicio

```bash
sudo systemctl status wolRepeater
```

## configuraciones adicionales

Hay que tener en cuenta el fichero de log que se genere y configurar el logrotate para que no se llene el disco inecesariamente

Por ejemplo podemos añadir el siguiente **/etc/logrotate.d/wolRepeater**

```data
/var/log/wolRepeater.log {

    daily
    rotate 2
    compress

    delaycompress
    missingok

    create 0640 wolrepeater root

    postrotate
        systemctl restart wolRepeater
    endscript
}
```

## Daisy Chain use

Podemos usar el script en cadena. Unservidor se configura para enviar paquetes con  _secureOn_ y un segundo servidor para recibirlos con  _secureOn_.

```mermaid
graph LR
  WS[WoL Sender]

  WS-->RSS

  RSS[Wol Repeater \nsend with SecureOn]

    RSS === RSR[SecureOn Enabled]

  RSR[Wol Repeater\nreceive with SecureOn]
    
    RSR --> MA

  MA[Final Machines]

```

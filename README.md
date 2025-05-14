# ZDay - HackMyVM (Hard)
 
![Zday.png](Zday.png)

## Übersicht

*   **VM:** ZDay
*   **Plattform:** (https://hackmyvm.eu/machines/machine.php?vm=Zday)
*   **Schwierigkeit:** Hard (im Titel erwähnt, obwohl der ursprüngliche Text "Medium" anzeigte, wurde dies im VM-Namen korrigiert)
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 11. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Zday_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "ZDay"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration mehrerer offener Ports, darunter FTP (anonymer Login nicht erwähnt, aber Standardprüfung), SSH, HTTP/HTTPS (Apache), NFS und MySQL. Entscheidend war die Entdeckung einer FOG Project-Installation im Verzeichnis `/fog/` auf Port 443 (HTTPS). Die Standard-Credentials (`fog:password`) ermöglichten den Login in die FOG-Management-Konsole. Dort wurden im Storage-Bereich weitere Credentials (`fogproject:84D1gia!8M9HSsR8gXau`) gefunden, die für den SSH-Login als `fogproject` funktionierten. Als `fogproject` wurde festgestellt, dass die NFS-Freigabe `/images/dev` von jedem Host gemountet werden konnte. Ein Versuch, eine SUID-Bash über NFS zu platzieren und auszuführen, scheiterte an GLIBC-Inkompatibilitäten. Stattdessen wurde eine PHP-Webshell (`image.php`) auf das Zielsystem heruntergeladen und in das FOG iPXE-Verzeichnis (`/var/www/html/fog/service/ipxe/index.php`) kopiert, was RCE als `www-data` ermöglichte. Als `www-data` zeigte `sudo -l`, dass `/usr/bin/dash` als Benutzer `estas` ausgeführt werden durfte. Dies wurde genutzt, um eine Shell als `estas` zu erhalten. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Schließlich erlaubte eine weitere `sudo`-Regel dem Benutzer `estas`, `/usr/bin/mimeopen` als `root` auszuführen. Durch Auswahl von "Other..." und Eingabe von `bash` als auszuführenden Befehl wurde eine Root-Shell erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `stegseek` (versucht, erfolglos)
*   `showmount`
*   `ssh`
*   `mkdir`
*   `mount`
*   `cp`
*   `chmod`
*   `ls`
*   `python3` (für `http.server` und Shell-Stabilisierung)
*   `wget`
*   `curl`
*   `nc` (netcat)
*   `sudo`
*   `echo`
*   `mimeopen` (als Exploit-Vektor)
*   `cat`
*   `id`
*   `pwd`
*   `cd`
*   `bash`
*   Standard Linux-Befehle (`vi`/`nano`, `stty`, `export`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "ZDay" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Service Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.145`).
    *   `nmap`-Scan identifizierte offene Ports: 21 (FTP), 22 (SSH), 80 (HTTP), 111 (RPCbind), 443 (HTTP), 2049 (NFS), 3306 (MySQL) und mehrere dynamische NFS-Ports.
    *   `showmount -e 192.168.2.145` offenbarte die NFS-Freigaben `/images/dev` und `/images` (beide für `*` zugänglich).
    *   `gobuster` auf Port 443 (`https://zday.vm:443`) fand das Verzeichnis `/fog/` (FOG Project).
    *   Weitere `gobuster`-Scans auf `/fog/management/` und `/fog/management/other/` identifizierten die FOG Management Console und ein `/ssl/`-Verzeichnis (enthielt `srvpublic.crt`).

2.  **Initial Access (FOG Credentials & PHP Webshell zu `www-data`):**
    *   Recherche nach FOG Project Standard-Credentials ergab `fog:password`.
    *   Login in die FOG Management Console (`https://zday.vm:443/fog/management/`) mit `fog:password`.
    *   Im Storage-Bereich der FOG-Konsole wurden die Credentials `fogproject:84D1gia!8M9HSsR8gXau` gefunden.
    *   Erfolgreicher SSH-Login als `fogproject` mit diesen Credentials.
    *   *Ein Versuch, eine SUID-Bash über die NFS-Freigabe `/images/dev` zu erstellen, scheiterte an GLIBC-Inkompatibilitäten.*
    *   Herunterladen einer PHP-Webshell (`image.php`) auf das Zielsystem (`/tmp/`) via Python HTTP-Server.
    *   Kopieren der Webshell nach `/var/www/html/fog/service/ipxe/index.php` (ersetzt die Originaldatei).
    *   Auslösen der Webshell durch Aufruf von `http://zday.vm/fog/service/ipxe/index.php` via `curl`.
    *   Erlangung einer interaktiven Reverse Shell als `www-data` nach Stabilisierung.

3.  **Privilege Escalation (von `www-data` zu `estas` via `sudo dash`):**
    *   `sudo -l` als `www-data` zeigte: `(estas) NOPASSWD: /usr/bin/dash`.
    *   Ausführung von `sudo -u estas /usr/bin/dash`.
    *   Erlangung einer Shell als Benutzer `estas`.
    *   User-Flag `whereihavebeen` in `/home/estas/user.txt` gelesen.

4.  **Privilege Escalation (von `estas` zu `root` via `sudo mimeopen`):**
    *   `sudo -l` als `estas` (impliziert, Information fehlt im Log, aber für den Exploit notwendig) offenbarte die Regel, `/usr/bin/mimeopen` als `root` ausführen zu dürfen.
    *   Erstellung einer Datei `/tmp/tmpfile` mit Inhalt `bash`.
    *   Ausführung von `sudo mimeopen -d /tmp/tmpfile`.
    *   Im interaktiven `mimeopen`-Prompt wurde Option `2` ("Other...") und dann `bash` als Befehl eingegeben.
    *   Da `mimeopen` als `root` lief, wurde `bash` ebenfalls als `root` gestartet.
    *   Erlangung einer Root-Shell.
    *   Root-Flag `ihavebeenherealways` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Offene NFS-Freigaben:** Zwei NFS-Shares waren für jeden im Netzwerk zugänglich.
*   **FOG Project Standard-Credentials:** Ermöglichten den Login in die Management-Konsole.
*   **Informationsleck in Webanwendung (FOG):** Interne Credentials (`fogproject`) wurden in der FOG-Oberfläche gefunden.
*   **Unsichere Dateiberechtigungen (Web-Verzeichnis):** Der Benutzer `fogproject` konnte Webserver-Dateien überschreiben, was das Platzieren einer Webshell ermöglichte.
*   **PHP Webshell / Remote Code Execution (RCE):** Durch das Ersetzen einer PHP-Datei im Web-Root.
*   **Unsichere `sudo`-Konfigurationen:**
    *   `www-data` durfte `/usr/bin/dash` als `estas` ausführen.
    *   `estas` durfte `/usr/bin/mimeopen` als `root` ausführen, was durch die interaktive Auswahl eines auszuführenden Befehls zur Eskalation genutzt wurde.

## Flags

*   **User Flag (`/home/estas/user.txt`):** `whereihavebeen`
*   **Root Flag (`/root/root.txt`):** `ihavebeenherealways`

## Tags

`HackMyVM`, `ZDay`, `Hard`, `NFS`, `FOG Project`, `Default Credentials`, `Webshell`, `RCE`, `PHP`, `sudo Exploitation`, `dash`, `mimeopen`, `Privilege Escalation`, `Linux`, `Web`

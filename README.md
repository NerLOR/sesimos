
# Necronda web server

Necronda is a lightweight webserver written in C.

Features include:

* TLS
* Reverse-Proxy
* Fast-CGI


## Configuration

Default Path: `/etc/necronda-server/necronda-server.conf`

Defualt FPM Socket Path: `/var/run/php-fpm/php-fpm.sock`

### Example Config

I have no clue what the hell this is 

```
certificate ~/certfile
private_key ~/privatekey
geoip_dir ~/geoips
dns_server 8.8.8.8

webroot /var/www/
dir_mode ??
hostname example.com
port 443

http
https
```



## Dependencies

### Debian

`sudo apt-get install gcc libmagic-dev libssl-dev php-fpm libmaxminddb-dev`

### Arch/Manjaro

`sudo pacman -Sy base-devel php-fpm libmaxminddb`


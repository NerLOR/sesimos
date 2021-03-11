//
// Created by lorenz on 17.01.21.
//

#include "fastcgi.c"
#include "http.c"
#include "sock.c"

const char *msg = "PHP message: PHP Notice:  Undefined index: Verifiedd in /srv/necronda/www.necronda.net/admin/users.php on line 58PHP message: PHP Notice:  Undefined index: Verifiedd in /srv/necronda/www.necronda.net/admin/users.php on line 58PHP message: PHP Notice:  Undefined index: Verifiedd in /srv/necronda/www.necronda.net/admin/users.php on line 58PHP message: PHP Notice:  Undefined index: Verifiedd in /srv/necronda/www.necronda.net/admin/users.php on line 58PHP message: PHP Notice:  Undefined index: Verifiedd in /srv/necronda/www.necronda.net/admin/users.php on line 58PHP message: PHP Notice:  Undefined index: Verifiedd in /srv/necronda/www.necronda.net/admin/users.php on line 58PHP message: PHP Notice:  Undefined index: Verifiedd in /srv/necronda/www.necronda.net/admin/users.php on line 58PHP message: PHP Notice:  Undefined index: Verifiedd in /srv/necronda/www.necronda.net/admin/users.php on line 58";

int main() {
    char err[256];
    int ret = fastcgi_php_error(msg, strlen(msg), err);
    printf("%i\n", ret);
    return 0;
}



# Architecture

* logger (1)
* listener (2) - 80, 443
* cache_handler (1)
* connection_initializer
* request_handler
* local_handler
* proxy_handler
* ws_handler
* fastcgi_handler


* -> logger
* main -> listener
* listener -> connection_handler
* connection_initializer -> request_handler
* request_handler -> local_handler -> request_handler
* local_handler -> fastcgi_handler -> request_handler
* request_handler -> rp_handler -> request_handler
* proxy_handler -> ws_handler -> request_handler

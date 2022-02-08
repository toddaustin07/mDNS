# mDNS
A Lua library for discovering devices (services) and their address via Multicast DNS.

This is intended to be a robust implementation, designed to be able to read and parse all valid DNS response records including proper handling of compressed labels.  The current code supports the following response record types:  A, PTR, SRV, TXT.  The API is quite simple to use and returns DNS response record data in easy-to-use Lua tables.


## API
A work in progress, but currently supports 3 APIs:

**scan**(<*service_class*>, <*type*>, <*duration*>)

- *service_class* - for example: \_http.\_tcp.local
- *type* - requested DNS response record type
- *duration* - number of seconds to scan

Returns table of discovered devices and their data (can include name, alternative domain names, IP address, port, device info; depends on record type returned)
  
  
**get_ip**(<*domain_name*>)

- domain_name - typically <*instancename*>.local 

Returns device table including IP address
  
  
**get:address**(<*domain_name*>, <*service_class*>)

- *domain_name* - typically <*instancename*>.local
- *service_class* - for example: \_http.\_tcp.local

Returns device table including both IP and port number

## Future additions
I may add a monitoring function for maintaining ongoing status on device presence, and notifications for new services

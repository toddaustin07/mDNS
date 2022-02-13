# mDNS
A Lua library for discovering devices (services) and their address via Multicast DNS.

In its current form, this library provides what is considered a 'one-shot query' capability.  The library itself does not monitor the multicast continuously or maintain a cache of valid response records.  The library's *query* API call could be used to mimic such an application today, however a full-function mDNS querier - which would include this capability for ongoing device/service presence monitoring - is being considered as a future expansion of this project.

The API is intended to be simple to use and not require deep understanding of the mDNS protocol.  Much of the behind-the-scenes DNS gorp is hidden and responses are provided in collated Lua tables for ease of parsing.  For those knowledgeable and wanting more direct control, one of the API calls available provides a more detailed and perscriptive way to define the desired query.

## SmartThings Edge
The code has now been ported to be used in a SmartThings Edge driver.  

### Usage in a SmartThings Edge driver
Create a subdirectory in the src directory of the driver hub package called '**mDNS**' and copy the init.lua file provided from the SmartThingsEdge directory in this repository into it.  Add a **require = 'mDNS'** statement to your Edge driver code and use the APIs as described below.

## API
A work in progress, but currently supports the APIs below.

Note that the SmartThings Edge version now implements callbacks, which is assumed below.

### query (<*domain_name*>, <*type*>, <*duration*>, <*callback*>)

(For the mDNS expert who wants more specific control)

- *domain_name* - valid DNS name depending query type
- *type* - requested DNS response record type (1=A, 12=PTR, 16=TXT, 33=SRV, 255=ANY)
- *duration* - number of seconds to scan
- *callback* - function called upon successful execution, with return data as below

Returns table of discovered devices and their data (can include name, alternative domain names, IP address, port, device info; depends on record type returned)
  
 
### get_service_types (<*callback*>)

No parameters required.

Returns table of all available service types 
 
 
### get_services (<*service_type*>, <*callback*>)

- *service_type* - typically in the form \_xxxxx.\_tcp.local
- *callback* - function called upon successful execution, with return data as below

Returns table of all available instances for the given service type.  Most devices will also return whatever info is available including ip address, hostnames, port number, and info table.
 
 
### get_ip (<*instance_name*> | <*hostname*>, <*callback*>)

- *instance_name* - typically in the form *instancename*.local 
- *hostname* - typically in the form *hostname*.local   (note that *hostname* may also be included in the table returned from **get_services**) 
- *callback* - function called upon successful execution, with return data as below

Returns IP address if found
  
  
### get_address (<*domain_name*>, <*callback*>)

- *domain_name* - a *fully qualified* domain name; must be <instance name>.<service type>.local, e.g. 'Philips Hue - 1A2F3B._hue._tcp.local'
- *callback* - function called upon successful execution, with return data as below

Returns IP and port number if found


### Update Log
02/08/22 01:02    Handle spaces in names; add processing for Authority and Additional Information records
                  Next: improve collating of records

02/10/22 22:50    Numerous updates and reworking of API; addition of SmartThings Edge version

02/12/22 18:80    Fix to compressed labels handling; enhanced collate to specify servicetypes lists
  
02/13/22 15:45    Changed 'scan' API to 'query'
                  SmartThings Edge version: changed APIs to implement callbacks

### Next Updates to be made
- tbd based on further testing


# mDNS
A Lua library for discovering devices (services) and their address via Multicast DNS.

In its current form, this library provides what is considered a 'one-shot query' capability.  The library itself does not monitor the multicast continuously or maintain a cache of valid response records.  The library's *query* API call could be used to mimic such an application today, however a full-function mDNS querier - which would include this capability for ongoing device/service presence monitoring - is being considered as a future expansion of this project.

The API is intended to be simple to use and not require deep understanding of the mDNS protocol.  Much of the behind-the-scenes DNS gorp is hidden and responses are provided in collated Lua tables for ease of parsing.  For those knowledgeable and wanting more direct control, one of the API calls available provides a more detailed and perscriptive way to define the desired query.

**JANUARY 2023 UPDATE:  SmartThings Edge now includes a built-in mDNS library, so most SmartThings Edge driver developers can use that instead of my library here. This library might still be of interest to those looking for more detail access to response data or the ability to watch the mDNS multicast for a configurable amount of time.**

## SmartThings Edge
The code was developed ultimately for use by a SmartThings Edge driver which runs on a SmartThings hub.  To use this library in a SmartThings Edge driver, create a subdirectory called '**mDNS**' off of the src directory of the driver hub package, and copy the init.lua file provided from the SmartThingsEdge directory in this repository into it.  Add a **require = 'mDNS'** statement to your Edge driver code and use the APIs as described below.

## Running on any computer
A version of this library (mDNS.lua in root code directory) is also available that can be run on any computer with Lua 5.3 or later + Lua sockets library.  It is quite useful to test various queries, see what reponses are received, and what data is returned.

A common issue when trying to run code utilizing multicast addresses is getting 'address already in use' errors.  This is an indication that some other process on the computer has already claimed port 5353 and is not sharing it.  These services or applications can often be terminated without harm.  Avahi, browsers, or any other mDNS-related applications may need to be shut down to free up port 5353.  Otherwise, other networking configuration may need to be done to ensure the port is shared. 

## Quick mDNS Primer

mDNS defines a way for services (i.e. applications or devices) on a **local** network to be discovered.  It is implemented through the use of a special multicast address on which all services can 'advertise' their presence and provide additional information about the service.  A querier can send a 'question' to the multicast address and all services will respond if they have relevant 'answers' to the question.  An answer is always in the form of a formated response record.  There are five types of these records generally used by mDNS participants:

- PTR - provides instances of a particular service type
- SRV - provides hostnames plus port numbers associated with the service
- TXT - provides a set of key/value pairs that provide select metadata about the service (e.g. model, serial number, etc.)
- A - provides an IPv4 address
- AAAA - provides an IPv6 address


### Service Types
All service types must have the format:
```
_<*typename*>._<[tcp | upd]>.local
```
And so some examples might be: \_http.\_tcp.local, \_printer.\_tcp.local, \_hue.\_tcp.local

### Response records: queries and answers
For each response record type requested in a query, there is a specific name format to use in order to get the expected results. The contents of the returned response record also varies by type.  This is summarized below:

#### PTR Records
- Input:  use a service type; such as '\_http.\_tcp.local'
- Returns:  Fully qualified service instance names with the form \<*instancename*\>.\<*servicetype*\>; e.g. Philps Hue - 1E73F9.\_hue.\_tcp.local
  
#### SRV Records
- Input: use an instance name with the form \<*instancename*\>.\<*servicetype*\>; e.g. Philps Hue - 1E73F9.\_hue.\_tcp.local
- Returns:  a list of hostnames or server names in the form of \<*hostname*\>.local; plus associated port number
  
#### TXT Records
- Input: use an instance name with the form \<*instancename*\>.\<*servicetype*\>; e.g. Philps Hue - 1E73F9._hue._tcp.local
- Returns: set of key/value pairs
  
#### A records
- Input: an instance name with the form \<*instancename*\>.\<*servicetype*\>; e.g. Philps Hue - 1E73F9.\_hue.\_tcp.local
        * OR *
        a hostname or server name in the form of \<*hostname*\>.local (obtained from SRV record)
- Returns: IPv4 address (no port number)

## API
There is really only one core API: **query()**.  The remaining APIs are wrappers that use this core API under the covers; they exist to simplify things for the developer and reduce the level of mDNS expertise needed to get productive use out of the library.

Pay close attention to the guidance below on what name formats are required for each wrapper API.  Using the wrong name format will typically result in no responses, or responses you don't want.

All APIs are implemented with a callback parameter, so have no direct return value.  Return data is passed to the callback provided. For the return table descriptions below, we will assume the table returned to the callback is called '*resptable*'

### Core API

#### query (<*domain_name*>, <*type*>, <*duration*>, <*callback*>)

(For the mDNS-knowledgeable who want more specific control)

- *domain_name* - valid DNS name depending query type
- *type* - requested DNS response record type (1=A, 12=PTR, 16=TXT, 33=SRV, 255=ANY)
- *duration* - number of seconds to scan
- *callback* - function called upon successful execution, with return data as below

Returns table of discovered services and associated metadata (depends on record type returned, but can include name, alternative domain names, IP address, port, service info)
  
 
### Wrapper APIs
#### get_service_types (<*callback*>)

- *callback* - function called upon successful execution, with return data as below

Returns table of all available service types:  resptable\['\_services.\_dns-sd.\_udp.local'\].servicetypes
 
#### get_services (<*service_type*>, <*callback*>, <*duration*>)

- *service_type* - typically in the form \_*xxxxx*.\_tcp.local
- *callback* - function called upon successful execution, with return data as below
- *duration* - number of seconds to scan

Returns table of all available instances for the given service type:  resptable\['\<*service_type*\>'\].instances

Most devices will also return whatever info is available including ip address, hostnames, port number, and info table.
 
 
#### get_ip (<*instance_name*> | <*host_name*>, <*callback*>)

- *instance_name* - typically in the form *instancename*.local 
- *host_name* - typically in the form *hostname*.local   (note that *hostname* could be included in the table returned from **get_services()**) 
- *callback* - function called upon successful execution, with return data as below

Returns IP address (string) if found
  
  
#### get_address (<*domain_name*>, <*callback*>)

- *domain_name* - a *fully qualified* domain name; must be \<*instance_name*\>.\<*service_type*\>, e.g. 'Philips Hue - 1A2F3B.\_hue.\_tcp.local'
- *callback* - function called upon successful execution, with return data as below

Returns IP (string) and port number (number) if found

## A Typical Discovery Sequence
### Step 1: Figure out the Service Type Name
In order to find a service on the network, you first need to know what service type that service is using.  For example, services that have web pages would announce an http service of type \_http.\_tcp.local; services with printing capabilities would announce a printer service of type \_printer.\_tcp.local, etc.  An official list of service type names are maintained here:  https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml.  However, manufacturers or service developers may choose to make up their own service type names, so some might not be officially registered.

A list of all service types available on your LAN can be gotten using the **get_service_types()** API.

### Step 2: Get a list of all service instances for a given service type
By providing a service type to the **get_services()** API, such as *\_printer.\_tcp.local*, you can get a list of all service instances that are available on the LAN.  An 'instance' is simply one particular service of the given type.  It will have a unique instance name plus the service type suffix, i.e. \<*serviceinstance*\>.\_*xxxxxxx*.\_tcp.local.
  
Quite often, services will return several pieces of additional information, so the table returned from the **get_services()** call may contain not only a list of the available service names, but for some of them it may also include associated hostnames, IP addresses, and/or addtional text information made up of key/value pairs.  Scanning the returned table for the presence of this additional information may negate the need for further queries.
  
### Step 3: Get the IP address of the service
If the IP address was not included in the returned table from Step 2, then an explicit query can be done using the **get_ip()** API.  If the port number is required as well, then use the **get_address()** API.  

In many cases, in order for a **get_ip()** request to return an IP, you have to use a hostname rather than the service instance name.  In those cases it may be more expedient to use the **get_address()** API instead, since it will attempt to determine the hostname automatically, freeing you from that interim step

If the developer wants to obtain the hostname themselves, this can be done using the **query()** API with an **SRV** record request.



## Update Log
02/08/22 01:02    Handle spaces in names; add processing for Authority and Additional Information records
                  Next: improve collating of records

02/10/22 22:50    Numerous updates and reworking of API; addition of SmartThings Edge version

02/12/22 18:80    Fix to compressed labels handling; enhanced collate to specify servicetypes lists
  
02/13/22 15:45    Changed 'scan' API to 'query'; SmartThings Edge version: changed APIs to implement callbacks & re-enabled multicast responses to expand results

02/19/22 20:10    Documentation updates

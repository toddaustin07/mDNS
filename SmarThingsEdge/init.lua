--[[
  Copyright 2021 Todd Austin

  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
  except in compliance with the License. You may obtain a copy of the License at:

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed under the
  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
  either express or implied. See the License for the specific language governing permissions
  and limitations under the License.


  DESCRIPTION
  
  Routines to discover DNS services and their addresses

  ** This borrows a few lines of code from a Lua mDNS resolve function authored by 
     Ross Tyler: https://github.com/rtyle/st-edge/blob/master/util/resolve.lua

--]]

local cosock = require "cosock"
local socket = require "cosock.socket"
--local socket = require "socket"
local log = require "log"

----------------------------------------------------------------------------------------------
--                          DNS Message Constants
----------------------------------------------------------------------------------------------

-- Header Flag bits

dnsFlag_QR =      0x8000                      -- QR: Query(0)/Response(1)
dnsFlag_OpCode =  0x7800                      -- OpCodes: Query(0), Notify(4), Update(5); always 0 for mDNS
dnsFlag_AA =      0x0400                      -- AA: Authoritative Answer
dnsFlag_TC =      0x0200                      -- TC: Truncated Answer
dnsFlag_RD =      0x0100                      -- RD: Recursion Desired
dnsFlag_RA =      0x0080                      -- RA: Recursion Available
dnsFlag_Z =       0x0040                      -- Z: Zero
dnsFlag_AD =      0x0020                      -- AD: Authentic Data
dnsFlag_CD =      0x0010                      -- CD: Checking Disabled
dnsFlag_RCODE =   0x000f                      -- RCODEs: (see below)

-- Response Codes

dnsRCODE_NoError =   0                        -- No error
dnsRCODE_FormErr =   1                        -- Format error
dnsRCODE_ServFail =  2                        -- Server Failure
dnsRCODE_NXDomain =  3                        -- Nonexistant domain
dnsRCODE_NotImp =    4                        -- Not implemented
dnsRCODE_Refused =   5                        -- Refused
dnsRCODE_YXDomain =  6                        -- Name exists but shouldn't
dnsRCODE_YXRRSet =   7                        -- RRSet exists but shouldn't
dnsRCODE_NXRRSet =   8                        -- RRSet doesn't exist but should
dnsRCODE_NotAuth =   9                        -- Server not authorized for zone
dnsRCODE_NotZone =   10                       -- Name not contained in zone

-- Resource Record Types

dnsRRType_A =        1                        -- IPv4 Address
dnsRRType_NS =       2                        -- Name server
dnsRRType_CNAME =    5                        -- Canonical name
dnsRRType_SOA =      6                        -- Start of authority
dnsRRType_PTR =      12                       -- Pointer
dnsRRType_MX =       15                       -- Mail exchanger
dnsRRType_TXT =      16                       -- Text info
dnsRRType_AAAA =     28                       -- IPv6 Address
dnsRRType_SRV =      33                       -- Server selection; transport endpoints
dnsRRType_NAPTR =    35                       -- Name authority pointer
dnsRRType_OPT =      41                       -- Pseudo-RR
dnsRRType_NSEC =     47                       -- Name does not exist
dnsRRType_IXFR =     251                      -- Incremental zone transfer
dnsRRType_AXFR =     252                      -- Full zone transfer
dnsRRType_ANY =      255                      -- Request for all records

dnsUnicast =         0x8000                   -- DNS re-purpose bit: Unicast response preferred bit in Class field of Question section
dnsCacheFlush =      0x8000                   -- DNS re-purpose bit: Cache flush bit in Class field of Answer section
dnsUniqueRRset =     0x8000                   -- DNS re-purpose bit: Record is member of unique RRSet; Class field of RR section

dnsClassInternet =    1
dnsClassNoClass =     254
dnsClassAllClass =    255

mdnsADDRESS =       "224.0.0.251"
mdnsPORT =          5353

-- Module variables

local listen_ip = "*"
local listen_port = 0

-- Module functions

function hex_dump (str)
    local len = string.len( str )
    local dump = ""
    local hex = ""
    local asc = ""
    
    for i = 1, len do
        if 1 == i % 8 then
            dump = dump .. hex .. asc .. "\n"
            hex = string.format( "%04x: ", i - 1 )
            asc = ""
        end
        
        local ord = string.byte( str, i )
        hex = hex .. string.format( "%02x ", ord )
        if ord >= 32 and ord <= 126 then
            asc = asc .. string.char( ord )
        else
            asc = asc .. "."
        end
    end
    
    return dump .. hex .. string.rep( "   ", 8 - len % 8 ) .. asc
end


local function init_sockets()

  local rc, msg

  ---[[
  -- Multicast socket

  local m = socket.udp()
  
  if not m then
    log.error ('UDP multicast socket creation failed')
    return
  end

  assert(m:setoption('reuseaddr', true))
  rc, msg = m:setsockname(mdnsADDRESS, mdnsPORT)
  if not rc then
    log.error ('multicast setsockname error:', msg)
    return
  end

  assert(m:setoption("ip-add-membership", {multiaddr = mdnsADDRESS, interface = "0.0.0.0"}), "join multicast group")
  --]]

  -- Unicast socket

  local u = socket.udp()
  
  if not u then
    log.error ('UDP unicast socket creation failed')
    return
  end
  
  rc, msg = u:setsockname(listen_ip, listen_port)
  if not rc then
    log.error ('unicast setsockname error:', msg)
    return
  end

  return m, u
  --return u

end


local function make_labels(name)

  local labels = {}
  
  for label in string.gmatch(name, "[^%.]+") do
    table.insert(labels, string.pack("> s1", label))
  end
  
  return(table.concat(labels))

end

local function dns_send(sock, rrtype, name)

  local labels = make_labels(name)

  local question = table.concat({
    string.pack("> I2 I2 I2 I2 I2 I2 z I2 I2",
                    -- [HEADER]
      0,                -- Transaction ID
      0,                -- Flags
      1,                -- Questions count
      0,                -- Answer count
      0,                -- Authority record count
      0,                -- Additional information count
                    -- [QUESTION SECTION]
      labels,           -- Host name labels
      rrtype,           -- Resource record query type (PTR, SRV, TXT, etc)
      dnsUnicast | dnsClassInternet    -- Class (always Internet)
    ),
  })

  --print ('Sending:')
  --print (hex_dump(question))
  
  local rc, msg
  rc, msg = sock:sendto(question, mdnsADDRESS, mdnsPORT)
  if not rc then
    log.error ('Send error:', msg)
    return
  else
    return true
  end

end


local function get_label(currlabel, fullmsg, compflag)
  
  local len = string.unpack("> B", currlabel)
  if len then
    if len > 0 then
      if len >= 0xc0 then
        local index = string.unpack("> I2", currlabel) - 0xc000
        local newlen = fullmsg:sub(index+1):byte()
        local _name = fullmsg:sub(index+2, index+1+newlen)
        local retlen
        if compflag == false then
          retlen = 2
        else
          retlen = 0
        end
        return _name, retlen, fullmsg:sub(index+1+newlen+1), true, false
      else
        local retlen
        if compflag == false then
          retlen = len + 1
        else
          retlen = 0
        end
        return currlabel:sub(2, 2+len-1), retlen, currlabel:sub(len+2), compflag, false
      end
    else
      return nil, nil, nil, compflag, true
    end
  else
    log.error ('***Error: unexpected null string length')
  end
end


local function build_name_from_labels(data, fullmsg)

  local name
  
  local totalnamelen = 0
  local nextlabel = data
  local compflag = false
  local endflag = false
  
  local _len = nextlabel:byte()
  local _name
  
  while (endflag == false) do
  
    _name, _len, nextlabel, compflag, endflag = get_label(nextlabel, fullmsg, compflag)

    --log.debug ('_name/_len:', _name, _len)

    if endflag == false then

      if name then
        name = name .. '.' .. _name
      else
        name = _name
      end
      
      totalnamelen = totalnamelen + _len
      
      --log.debug (string.format('\tNext Label length: 0x%02X', nextlabel:byte())) 
      --log.debug (string.format('\tNext label: >%s<', nextlabel:sub(2, 40)))
    
    end
    
  end
  
  local suffixdata
  
  if compflag == false then
    totalnamelen = totalnamelen + 1         -- account for null terminator
  end  
    
  suffixdata = data:sub(totalnamelen+1)
  
  --log.debug ('Built name:', name, totalnamelen)
  
  return name, totalnamelen, suffixdata

end



local function parse_question(question, fullmsg)

  -- Get question name from labels
  local name, namefieldlen, suffix_data = build_name_from_labels(question, fullmsg)

  -- Parse remainder of resource record
  local rrtype, class = string.unpack("> I2 I2", suffix_data)
  
  -- Return object table
  return  {
            ['name'] = name,
            ['type'] = rrtype,
            ['class'] = class,
            ['recordlen'] = namefieldlen + 4
          }
end


local function parse_section(section, fullmsg)

  -- Build host name from labels
  local name, namefieldlen, suffix_data = build_name_from_labels(section, fullmsg)

  -- Parse remainder of resource record
  local
      rrtype,
      class,
      ttl,             
      length
    = string.unpack("> I2 I2 I4 I2", suffix_data)
  
  -- Return object table
  return  {
            ['name'] = name,
            ['type'] = rrtype,
            ['class'] = class,
            ['ttl'] = ttl,
            ['rdlength'] = length,
            ['rdata'] = suffix_data:sub(11, 11 + length - 1),
            ['recordlen'] = namefieldlen + 10 + length
          }
end


local function parse_txt(txt)

  local itemlen = txt:byte()
  local nextitem = txt:sub(2)
  
  local itemtable = {}
  
  if itemlen > 0 then
  
      while itemlen ~= nil do
       
        local item = nextitem:sub(1, itemlen)
        local key, value = item:match('^(.+)=(.+)$')
        -- handle case where there is no value 
        if not key then
          key = item:match('^(.+)=')        -- try to get key without value
          if key then
            itemtable[key] = ''
          else
            log.error ("ERROR parsing key")
          end
        else
          if value then
            itemtable[key] = value
          else
            itemtable[key] = ''
          end
        end
        
        local next = itemlen
        itemlen = nextitem:sub(next+1):byte()
        nextitem = nextitem:sub(next+2)
      end
      return itemtable
      
  end
end


local function parse_srv(data, fullmsg)

  local
        priority,         -- Host priority
        weight,           -- Relative weight
        port              -- Host port #
    = string.unpack("> I2 I2 I2", data)

  local hostname = build_name_from_labels(data:sub(7), fullmsg)
  
  return hostname, port

end

local function process_response(msgdata)

  -- Unpack HEADER
  local
        transaction_id,     -- Transaction ID
        flags,              -- Flags
        qdcount,            -- Query count
        ancount,            -- Answer count
        nscount,            -- Authority record count
        arcount             -- Additional info count
    = string.unpack("> I2 I2 I2 I2 I2 I2", msgdata)
  
  if transaction_id == 0 then                      -- ensure it's 0

    local targetflags = dnsFlag_QR | dnsFlag_AA
    if (flags & targetflags) == targetflags then
    
      local next_section = msgdata:sub(13)
      
      -- If question(s) included, parse past them (ignore)
      if qdcount > 0 then
        for item = 1, qdcount do
          local question_record  = parse_question(next_section, msgdata)
          next_section = next_section:sub(question_record.recordlen + 1)
        end
      end
          
      local sectioncount = ancount + nscount + arcount
      
      if sectioncount >= 1 then                       -- ensure at least 1 section
        
        local record_table = {}
        
        for item = 1, sectioncount do

          local section_record  = parse_section(next_section, msgdata)
          
          if section_record.type == dnsRRType_A then
          
            if section_record.rdlength == 4 then
          
              local a,b,c,d = string.unpack("> BBBB", section_record.rdata)
          
              local address = table.concat({a, b, c, d}, ".")
              
              table.insert(record_table, 
                              { ['Name'] = section_record.name,
                                ['IP'] = address,
                                ['RRtype'] = 'A',
                              })
            end
            
          elseif section_record.type == dnsRRType_PTR then
          
            local domain = build_name_from_labels(section_record.rdata, msgdata)
            
            local keyname
            if section_record.name == '_services._dns-sd._udp.local' then
              keyname = 'ServiceType'
            else
              keyname = 'Instance'
            end
            
            log.debug (string.format('PTR record: %s / %s', section_record.name, domain))
            
            table.insert(record_table, 
                              { ['Name'] = section_record.name,
                                [keyname] = domain,
                                ['RRtype'] = 'PTR',
                              })
            
          elseif section_record.type == dnsRRType_SRV then
          
            local hostname, port = parse_srv(section_record.rdata, msgdata)
            
            table.insert(record_table, 
                              { ['Name'] = section_record.name,
                                ['Hostname'] = hostname,
                                ['Port'] = port,
                                ['RRtype'] = 'SRV'
                              })
          
          elseif section_record.type == dnsRRType_TXT then
          
            local txt_table = parse_txt(section_record.rdata)
            
            table.insert(record_table, 
                              { ['Name'] = section_record.name,
                                ['Info'] = txt_table,
                                ['RRtype'] = 'TXT',
                              })
            
          --else
            --print (string.format('\tUnprocessed Record type (%d) received', section_record.type))
          end
          
          next_section = next_section:sub(section_record.recordlen + 1)
          
        end
        
        return record_table
        
      else
        log.warn ('Warning; No response records')
      end
    --else
      --print ('Not authoritative answer')
    end
  else
    log.warn ('Warning: Transaction ID not 0')
  end
    
end


local function strip_local(name)

  local i = name:find('.local', 1, 'plaintext')
  if i then
    return (name:sub(1, i-1))
  else
    return name
  end

end


local function collect(name, rrtype, listen_time, queryflag, instancename)

  m, u = init_sockets()
  --u = init_sockets()
  
  if u then
  
    if dns_send(u, rrtype, name) then
    
      socket.sleep(0.1)
      local timeouttime = socket.gettime() + listen_time + .5 -- + 1/2 for network delay
      
      local return_object = {}
      
      while true do
        local time_remaining = math.max(0, timeouttime-socket.gettime())
        local readysocks, err = socket.select({u, m}, {}, time_remaining)
        
        time_remaining = math.max(0, timeouttime-socket.gettime())
        
        if time_remaining > 0 then
          if readysocks then
          
            for _, sock in ipairs(readysocks) do
          
              local response_data, rip, _ = sock:receivefrom()
              
              if response_data then
              
                if sock == m then
                  log.debug (string.format('Multicast response received from %s', rip))
                else
                  log.debug (string.format('Unicast response received from %s', rip))
                end
                -- log.debug (string.format('Received response from %s:', rip))
                -- log.debug (hex_dump(response_data))
                
                local records = process_response(response_data)
                
                if records then
                
                  if queryflag == true then
                    local _name = name
                    if instancename then _name = instancename; end
                  
                    for i = 1, #records do
                      for key, value in pairs(records[i]) do
                        if strip_local(records[i].Name) == strip_local(_name) then
                          m:close()
                          u:close()
                          return records
                        end
                      end
                    end
                  else
                    table.insert(return_object, records)
                  end
                end
              else
                log.error ('Receive error = ', rip)
              end
            end
          else
            log.warn (string.format('No sockets ready; time left=%f', time_remaining))
          end
        else
          break
        end
      end
      m:close()
      u:close()
      return return_object
    end
    m:close()
    u:close()
  end
end

local function consolidate(rrtable, key, value)

  if not rrtable[key] then
    rrtable[key] = {}
  end
  local found = false
  for _, thing in ipairs(rrtable[key]) do
    if thing == value then found = true; end
  end
  if not found then
    table.insert(rrtable[key], value)
  end

end

local function collate(collection)
  
  local collated = {}
  
  for _, group in ipairs(collection) do
    for _, records in ipairs(group) do
      local instance
      for key, value in pairs(records) do
        if key == 'Name' then
          name = value
          if not collated[name] then
            collated[name] = {}
          end
        end
      end
          
      for key, value in pairs(records) do
        if key == 'IP' then
          collated[name].ip = value
        elseif key == 'Port' then
          collated[name].port = value
        elseif key == 'Instance' then
          consolidate(collated[name], 'instances', value)
        elseif key == 'ServiceType' then
          consolidate(collated[name], 'servicetypes', value)
        elseif key == 'Hostname' then
          consolidate(collated[name], 'hostnames', value)
        elseif key == 'Info' then
          collated[name].info = value
        end
      end
      
    end
  end
  
  return collated

end


local function scan(name, rrtype, listen_time)

  if name and rrtype and listen_time then

    local collection = collect(name, rrtype, listen_time, false)
    
    if collection then
    
      return (collate(collection))
      
    end
  else
    log.error ('Missing parameter(s) for query() or scan()')
  end
end


local function query(name, rrtype, listen_time, callback)

  if callback then
    callback (scan(name, rrtype, listen_time))
  else
    log.error ('Missing callback parameter for query()')
  end

end


local function get_service_types(callback)

  if callback then
    callback (scan('_services._dns-sd._udp.local', dnsRRType_ANY, 2))
  else
    log.error ('Missing callback parameter for get_service_types()')
  end

end


local function get_services(servtype, callback)

  if servtype and callback then

    local collection = collect(servtype, dnsRRType_PTR, 2, false)
    
    if collection then
    
      callback (collate(collection))
      
    end
  else
    log.error ('Missing parameters for get_services()')
  end
end

local function get_ip(instancename, callback)

  if instancename and callback then
    local records = collect(instancename, dnsRRType_A, 1, true)
    if records then
      for i = 1, #records do
        for key, value in pairs(records[i]) do
          if key == 'IP' then
            callback(value)
          end
        end
      end
    end
  else
    log.error ('Missing parameters for get_ip()')
  end
end

local function get_address(domainname, callback)

  if domainname and callback then
  
    local ip, port
    
    local instancename = domainname:match('^([^%.]+)%.')
    if not instancename then
      log.error ('Invalid domain name provided')
      return
    else
      if instancename:sub(1,1) == '_' then
        log.error ('Invalid domain name provided')
        return
      end
    end
    local class = '_' .. domainname:match('_(.+)')
    if not class then
      log.error ('Service type not found')
      return
    end
  
    -- First try PTR requests, as the response may have both IP and port
    
    records = collect(class, dnsRRType_PTR, 1.5, true, instancename)
    if records then
      for i = 1, #records do
        for key, value in pairs(records[i]) do
          if key == 'Port' then
            port = value
          elseif key == 'IP' then
            ip = value
          end
        end
      end
      
      if ip and port then
        callback (ip, port)
      end
    end
    
    -- If IP & port not gotten from PTR query, try getting IP and port separately
    
    -- Step 1: Try an SRV request, as its returned hostname may be needed to get IP
      local hostname
      records = collect(domainname, dnsRRType_SRV, 1, true)
      if records then
        for i = 1, #records do
          for key, value in pairs(records[i]) do
            if key == 'Port' then
              port = value
            elseif key == 'Hostname' then
              hostname = value
            end
          end
        end
      end
    
    if not hostname then
      log.warn ('No hostname found for', domainname)
    end
    socket.sleep(.1)
    
    -- Step 2: Try an IP ('A') Request with <instancename>.local
    local records = collect(instancename .. '.local', dnsRRType_A, 1, true)
    if records then
      for i = 1, #records do
        for key, value in pairs(records[i]) do
          if key == 'IP' then
            ip = value
          end
        end
      end

      if ip and port then
        callback(ip, port)
      else
        if hostname then
        -- Step 3: Try an IP ('A') Request with hostname from SRV record
          local records = collect(hostname, dnsRRType_A, 1, true)
          if records then
            for i = 1, #records do
              for key, value in pairs(records[i]) do
                if key == 'IP' then
                  ip = value
                end
              end
            end
          end
        end  
        callback(ip, port)
      end
    end
  else
    log.error ('Missing parameters get_address()')
  end
end

return  {
          query = query,
          get_service_types = get_service_types,
          get_services = get_services,
          get_address = get_address,
          get_ip = get_ip,
        }

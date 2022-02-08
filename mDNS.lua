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

--local cosock = require "cosock"
local socket = require "socket"

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


local function init_socket()

  local m = socket.udp()
  
  if not m then
    print ('UDP socket creation failed')
    return
  end

  local rc, msg = m:setsockname(listen_ip, mdnsPORT)
  if not rc then
    print ('setsockname error:', msg)
    return
  end

  assert(m:setoption("ip-add-membership", {multiaddr = mdnsADDRESS, interface = "*"}), "join multicast group")

  return m

end

local function make_labels(name)

  local labels = {}
  
  for label in string.gmatch(name, "[^%.]+") do
    table.insert(labels, string.pack("> s1", label))
  end
  
  return(table.concat(labels))

end

local function dns_send(m, rrtype, name)

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
      dnsClassInternet  -- Class (always Internet)
    ),
  })

  --print ('Sending:')
  --print (hex_dump(question))
  
  local rc, msg
  rc, msg = m:sendto(question, mdnsADDRESS, mdnsPORT)
  if not rc then
    print ('Send error:', msg)
    return
  else
    return true
  end

end


local function get_label(nameptr, fullmsg)
  
  local len = string.unpack("> B", nameptr)
  if len then
    if len > 0 then
      if len >= 0xc0 then
        local index = string.unpack("> I2", nameptr) - 0xc000
        local newlen = fullmsg:sub(index+1):byte()
        local _name = fullmsg:sub(index+2, index+1+newlen)
        return _name, 2, true
      else
        return nameptr:sub(2, 2+len-1), len + 1, false
      end
    else
      return _, len, false
    end
  else
    print ('***Error: unexpected null string length')
  end
end


local function build_name_from_labels(data, fullmsg)

  local name = nil
  
  local totalnamelen = 0
  local nxtlblidx = 1
  
  local _len = data:byte()
  local _name
  local endflag = false
  
  while (_len > 0) and (not endflag) do
  
    _name, _len, endflag = get_label(data:sub(nxtlblidx), fullmsg)
    --print ('_name/_len:', _name, _len, endflag)
    if _len then
      if _len > 0 then
        if name then
          name = name .. '.' .. _name
        else
          name = _name
        end
        totalnamelen = totalnamelen + _len
         
        if not endflag then
          --print ('Current label:', data:sub(nxtlblidx+1, nxtlblidx+40))
          
          nxtlblidx = nxtlblidx + _len
          --print (string.format('Next label: >%s<', data:sub(nxtlblidx+1, nxtlblidx+40)))
          --print (string.format('\t%02X', data:sub(nxtlblidx):byte()))
        end
      end
    else
      print ('***Error: no string length found')
    end
  end
  
  local suffixdata
  
  if _len == 0 then
    totalnamelen = totalnamelen + 1         -- account for null terminator
    suffixdata = data:sub(nxtlblidx+1)
  elseif endflag then
    suffixdata = data:sub(nxtlblidx+2)
  else
    suffixdata = data:sub(nxtlblidx)        -- this shouldn't happen
    print ('***UNEXPECTED ERROR: ~0 len & endflag false') 
  end
  
  --print ('built name:', name, totalnamelen)
  
  return name, totalnamelen, suffixdata

end

local function parse_answer(answer, fullmsg)

  -- Build host name from labels
  local name, namefieldlen, suffix_data = build_name_from_labels(answer, fullmsg)

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
            print ("ERROR parsing key")
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
      
  else
    print ('Warning: 0 length TXT data')
  end
end


local function parse_srv(data, fullmsg)

  local
        priority,         -- Host priority
        weight,           -- Relative weight
        port              -- Host port #
    = string.unpack("> I2 I2 I2", data)

  local domainname = build_name_from_labels(data:sub(7), fullmsg)
  
  return domainname, port

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
    
      if ancount >= 1 then                       -- ensure at least 1 answer
        
        local record_table = {}
        
        local next_answer = msgdata:sub(13)
          
        for item = 1, (ancount+nscount+arcount) do

          local answer_record  = parse_answer(next_answer, msgdata)
          
          if answer_record.type == dnsRRType_A then
          
            if answer_record.rdlength == 4 then
          
              local a,b,c,d = string.unpack("> BBBB", answer_record.rdata)
          
              local address = table.concat({a, b, c, d}, ".")
              
              table.insert(record_table, 
                              { ['Name'] = answer_record.name,
                                ['IP'] = address,
                                ['RRtype'] = 'A',
                              })
            end
            
          elseif answer_record.type == dnsRRType_PTR then
          
            local domain = build_name_from_labels(answer_record.rdata, msgdata)
            
            table.insert(record_table, 
                              { ['Domain'] = answer_record.name,
                                ['Name'] = domain,
                                ['RRtype'] = 'PTR',
                              })
            
            
          elseif answer_record.type == dnsRRType_SRV then
          
            local domain, port = parse_srv(answer_record.rdata, msgdata)
            
            table.insert(record_table, 
                              { ['Name'] = answer_record.name,
                                ['Domain'] = domain,
                                ['Port'] = port,
                                ['RRtype'] = 'SRV'
                              })
          
          elseif answer_record.type == dnsRRType_TXT then
          
            local txt_table = parse_txt(answer_record.rdata)
            
            table.insert(record_table, 
                              { ['Name'] = answer_record.name,
                                ['Info'] = txt_table,
                                ['RRtype'] = 'TXT',
                              })
            
          --else
            --print (string.format('\tUnprocessed Record type (%d) received', answer_record.type))
          end
          
          next_answer = next_answer:sub(answer_record.recordlen + 1)
          
        end
        
        return record_table
        
      else
        print ('Answer count not > 0')
      end
    --else
      --print ('Not authoritative answer')
    end
  else
    print ('Transaction ID not 0')
  end
    
end

local function dump_to_file(records)

  local logfile = io.open ('./mdns.log', 'a')
  local writerec
              
  for i, value1 in ipairs(records) do
    writerec = string.format('\nRecord #%d:\n', i)
    logfile:write (writerec)
    for key, value2 in pairs(value1) do
      writerec = string.format('\t%s: %s\n',key, value2)
      logfile:write (writerec)
    end
  end
  logfile:write ('--------------------------------------------------\n')
  logfile:close()

end

local function collect(name, rrtype, listen_time, queryflag, instancename)

  m = init_socket()
  
  if m then
  
    if dns_send(m, rrtype, name) then
    
      socket.sleep(0.1)
      local timeouttime = socket.gettime() + listen_time + .5 -- + 1/2 for network delay
      
      local return_object = {}
      
      while true do
        local time_remaining = math.max(0, timeouttime-socket.gettime())
        m:settimeout(time_remaining)
      
        local response_data, rip, _ = m:receivefrom()
        if response_data then
        
          print (string.format('Received response from %s:', rip))
          print (hex_dump(response_data))
          
          local records = process_response(response_data)
          
          if records then
            dump_to_file(records)
          
            if queryflag == true then
              local _name = name
              if instancename then _name = instancename; end
            
              for i = 1, #records do
                for key, value in pairs(records[i]) do
                  if records[i].Name == _name then
                    m:close()
                    return records
                  end
                end
              end
            else
              table.insert(return_object, records)
            end
          end
          
        elseif rip == 'timeout' then
          break
        else  
          print ('Receive error = ', rip)
        end
      end
      m:close()
      return return_object
    end
    m:close()
  end
end


local function collate(collection)
  
  local collated = {}
  
  for _, group in ipairs(collection) do
    for _, records in ipairs(group) do
      local instance
      for key, value in pairs(records) do
        if key == 'Name' then
        
          instance = value:match('^([^%.]+)%.')
          if not instance then
            instance = value
          end
          
          if not collated[instance] then
            collated[instance] = {}
            collated[instance].domains = {}
            --table.insert(collated[instance].domains, value)
          end
        end
      end
          
      for key, value in pairs(records) do
        if key == 'IP' then
          collated[instance].IP = value
        elseif key == 'Port' then
          collated[instance].port = value
        elseif (key == 'Query') or (key == 'Domain') or (key == 'Target') then
          if not collated[instance].domains then
            collated[instance].domains = {}
          end
          local found = false
          for _, domain in ipairs(collated[instance].domains) do
            if domain == value then found = true; end
          end
          if not found then
            table.insert(collated[instance].domains, value)
          end
        elseif key == 'Info' then
          collated[instance].info = value
        end
      end
      
    end
  end
  
  return collated

end


local function scan(name, rrtype, listen_time)

  print ('scan input:', name, rrtype, listen_time)

  local collection = collect(name, rrtype, listen_time, false)
  
  if collection then
  
    return (collate(collection))
    
  end
end

local function get_ip(instancename)

  local records = collect(instancename, dnsRRType_A, 1, true)
  if records then
    return (collate({ records }))
  end
  
end

local function get_address(instancename, class)

  local collection = {}
  
  -- First try PTR requests, as it may have both IP and port
  
  print ('PTR Request')
  records = collect(class, dnsRRType_PTR, 1, true, instancename)
  if records then
    
    local found = 0
    for i = 1, #records do
      for key, value in pairs(records[i]) do
        if key == 'Port' then
          found = found + 1
          table.insert(collection, records)
        elseif key == 'IP' then
          found = found + 1
          table.insert(collection, records)
        end
      end
    end
    
    if found == 2 then
      return (collate(collection))
    end
  end
  -- Try getting IP and port separately
  
  print ('A Request')
  local records = collect(instancename, dnsRRType_A, 1, true)
  if records then
    table.insert(collection, records)
    
    socket.sleep(.1)
    
    print ('SRV Request')
    records = collect(class, dnsRRType_SRV, 1, true, instancename)
    if records then
      table.insert(collection, records)
      return (collate(collection))
    end
  end
end

return  {
          scan = scan,
          get_address = get_address,
          get_ip = get_ip,
        }

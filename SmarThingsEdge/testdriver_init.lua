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
  
  mDNS Discovery Driver

--]]

-- Edge libraries
local capabilities = require "st.capabilities"
local Driver = require "st.driver"
local cosock = require "cosock"                 -- just for time
local socket = require "cosock.socket"          -- just for time
local log = require "log"

-- Driver modules
local mDNS = require "mDNS"

-- Global variables
local devcounter = 1

-- Module variables
local thisDriver
local initialized = false
local lastinfochange = socket.gettime()

local cap_select = capabilities["partyvoice23922.mdnsselect"]
local cap_input = capabilities["partyvoice23922.mdnsinput"]
local cap_response = capabilities["partyvoice23922.mdnsresponse"]


local function disptable(intable, tab, maxlevels, currlevel)

	if not currlevel then; currlevel = 0; end
  currlevel = currlevel + 1
  for key, value in pairs(intable) do
    if type(key) ~= 'table' then
      print (tab .. '  ' .. key, value)
    else
      print (tab .. '  ', key, value)
    end
    if (type(value) == 'table') and (currlevel < maxlevels) then
      disptable(value, '  ' .. tab, maxlevels, currlevel)
    end
  end
end


local function build_html(list)

  local html_list = ''

  for _, item in ipairs(list) do
    html_list = html_list .. '<H6 style="margin:0">' .. item .. '</H6>\n'
  end

  local html =  {
                  '<!DOCTYPE html>\n',
                  '<HTML>\n',
                  '<BODY>\n',
                  html_list,
                  '</BODY>\n',
                  '</HTML>\n'
                }
    
  return (table.concat(html))
end


local function parse_types(resptable)

  return build_html(resptable['_services._dns-sd._udp.local'].servicetypes)

end


local function parse_services(resptable, type)

  return build_html(resptable[type].instances)

end


-----------------------------------------------------------------------
--										COMMAND HANDLERS
-----------------------------------------------------------------------


local function handle_selection(driver, device, command)

  log.debug("Selection = " .. command.command, command.args.value)
  
  device:emit_event(cap_select.cmdSelect(command.args.value))
  device.thread:call_with_delay(3, function() device:emit_event(cap_select.cmdSelect(" ")); end, 'clear cmd')
  
  if command.args.value == 'types' then
  
    log.debug ('Service types Request')
    local resptable = mDNS.get_service_types()
    
    if resptable then
      device:emit_event(cap_response.response(parse_types(resptable)))
    end
    
  elseif command.args.value == 'serv' then
    local name = device.state_cache.main['partyvoice23922.mdnsinput'].input.value
    log.debug (string.format('Services Request for >>%s<<', name))
    local resptable = mDNS.get_services(name)
    if resptable then
      device:emit_event(cap_response.response(parse_services(resptable, name)))
    end
  
  elseif command.args.value == 'getip' then
    local name = device.state_cache.main['partyvoice23922.mdnsinput'].input.value
    log.debug (string.format('IP Request for >>%s<<', name))
    local ip = mDNS.get_ip(name)
    if ip then
      device:emit_event(cap_response.response(string.format('%s',ip)))
    end
  
  elseif command.args.value == 'getaddr' then 
    local name, ctype = device.state_cache.main['partyvoice23922.mdnsinput'].input.value:match('([^,]+), (.+)$')
    log.debug (string.format('Address Request for name=>%s<, type=>%s<', name, ctype))
    local ip, port = mDNS.get_address(name, ctype)
    if ip then
      device:emit_event(cap_response.response(string.format('%s:%s',ip,port)))
    end
    
  end
  
end


local function handle_input(_, device, command)

  log.debug ('Input =', command.args.input)
  
  device:emit_event(cap_input.input(command.args.input))
  
end


------------------------------------------------------------------------
--                REQUIRED EDGE DRIVER HANDLERS
------------------------------------------------------------------------

-- Lifecycle handler to initialize existing devices AND newly discovered devices
local function device_init(driver, device)
  
  log.debug(device.id .. ": " .. device.device_network_id .. "> INITIALIZING")

  initialized = true
  device:online()
  
end


-- Called when device was just created in SmartThings
local function device_added (driver, device)

  log.info(device.id .. ": " .. device.device_network_id .. "> ADDED")
  
  
end


-- Called when SmartThings thinks the device needs provisioning
local function device_doconfigure (_, device)

  -- Nothing to do here!

end


-- Called when device was deleted via mobile app
local function device_removed(_, device)
  
  log.warn(device.id .. ": " .. device.device_network_id .. "> removed")
  
  --initialized = false
  
end


local function handler_driverchanged(driver, device, event, args)

  log.debug ('*** Driver changed handler invoked ***')

end


local function handler_infochanged (driver, device, event, args)

  log.debug ('Info changed handler invoked')

  local timenow = socket.gettime()
  local timesincelast = timenow - lastinfochange

  log.debug('Time since last info_changed:', timesincelast)
  
end


-- Create Primary Creator Device
local function discovery_handler(driver, _, should_continue)
  
  if not initialized then
  
    log.info("Creating mDNS device")
    
    local MFG_NAME = 'SmartThings Community'
    local VEND_LABEL = 'mDNS Discovery'
    local MODEL = 'mdnsdiscoveryv1'
    local ID = 'mdnsdiscovery' .. '_' .. socket.gettime()
    local PROFILE = 'mdnsdiscovery.v1'

    -- Create master device
	
		local create_device_msg = {
																type = "LAN",
																device_network_id = ID,
																label = VEND_LABEL,
																profile = PROFILE,
																manufacturer = MFG_NAME,
																model = MODEL,
																vendor_provided_label = VEND_LABEL,
															}
												
		assert (driver:try_create_device(create_device_msg), "failed to create device")
    
    log.debug("Exiting device creation")
    
  else
    log.info ('Device already created')
  end
end


-----------------------------------------------------------------------
--        DRIVER MAINLINE: Build driver context table
-----------------------------------------------------------------------
thisDriver = Driver("thisDriver", {
  discovery = discovery_handler,
  lifecycle_handlers = {
    init = device_init,
    added = device_added,
    driverSwitched = handler_driverchanged,
    infoChanged = handler_infochanged,
    doConfigure = device_doconfigure,
    removed = device_removed
  },
  
  capability_handlers = {
  
    [cap_select.ID] = {
      [cap_select.commands.setSelect.NAME] = handle_selection,
    },
    [cap_input.ID] = {
      [cap_input.commands.setInput.NAME] = handle_input,
    },
  }
})

log.info ('mDNS Discovery Demonstration Driver Started')

thisDriver:run()

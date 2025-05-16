####################
 cisco-wcl.nse
####################

-- Cisco Wireless LAN Controller (WLC) Version Detection
-- Extracts the version number from the web interface on port 443

local http = require "http"
local shortport = require "shortport"

description = [[
Detects the version of Cisco Wireless LAN Controller (WLC) by parsing the
JavaScript source URL from the web interface on port 443.
]]

author = "Tim Fowler - BHIS"
license = "Same as Nmap"
categories = {"discovery", "version"}

portrule = shortport.port_or_service(443, "https")

action = function(host, port)
    -- Perform HTTP GET request to the root path
    local response = http.get(host, port, "/")
    if not response then
        return "Failed to retrieve response from the server."
    end

    -- Check for response status
    if response.status ~= 200 then
        return "Unexpected HTTP response: " .. response.status
    end

    -- Extract the version from the script tag using Lua pattern matching
    local script_pattern = "<script[^>]*src=['\"][^'\"]+jquery[^?]+%?ver=([0-9%.]+)['\"]"
    local version = response.body:match(script_pattern)

    if version then
        return "Cisco WLC Version: " .. version
    else
        return "Version information not found in the web interface."
    end
end
####################
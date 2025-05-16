local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects Dell Integrated Remote Access Controller (iDRAC) versions and firmware information.
The script queries multiple endpoints to retrieve:
1. Overall iDRAC version from /restgui/locale/strings/locale_str_en.json and dynamic pages.
2. Firmware version and build information from /sysmgmt/2015/bmc/info.
3. Specific detection for iDRAC 8 via /session?aimGetProp=fwVersionFull.
]]

author = "Tim Fowler and Sean Verity - BHIS"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery"}

-- Ports typically used by iDRAC: 80 (HTTP), 443 (HTTPS)
portrule = shortport.port_or_service({80, 443}, {"http", "https"})

-- Function to get iDRAC version from /restgui/locale/strings/locale_str_en.json
local function get_idrac_version(host, port)
    local uri = "/restgui/locale/strings/locale_str_en.json"
    local headers = { ["Accept-Encoding"] = "gzip, deflate, br" }
    local response = http.get(host, port, uri, { timeout = 5000, header = headers })

    if response and response.status == 200 then
        if response.body and #response.body > 0 then
            local app_title = response.body:match('"app_title"%s*:%s*"([^"]+)"')
            local app_name = response.body:match('"app_name"%s*:%s*"([^"]+)"')
            if app_title and app_name then
                return string.format("%s (%s)", app_name, app_title)
            elseif app_name then
                return app_name
            end
        end
    end
    return nil
end

-- Function to get firmware version from /sysmgmt/2015/bmc/info
local function get_firmware_info(host, port)
    local uri = "/sysmgmt/2015/bmc/info"
    local response = http.get(host, port, uri, { timeout = 5000 })

    if response and response.status == 200 then
        if response.body and #response.body > 0 then
            local fw_ver = response.body:match('"FwVer"%s*:%s*"([%d%.]+)"')
            local build_ver = response.body:match('"BuildVersion"%s*:%s*"(%d+)"')
            if fw_ver and build_ver then
                return string.format("Firmware Version: %s (Build %s)", fw_ver, build_ver)
            elseif fw_ver then
                return string.format("Firmware Version: %s", fw_ver)
            end
        end
    end
    return nil
end

-- Function to detect iDRAC 8 via /session?aimGetProp=fwVersionFull
local function detect_idrac8(host, port)
    local uri = "/session?aimGetProp=fwVersionFull"
    local response = http.get(host, port, uri, { timeout = 5000 })

    if response and response.status == 200 then
        if response.body and #response.body > 0 then
            local fw_ver_full = response.body:match('"fwVersionFull"%s*:%s*"(.-)"')
            if fw_ver_full then
                return string.format("iDRAC 8 Firmware: %s", fw_ver_full)
            end
        end
    end
    return nil
end

-- Main action function
action = function(host, port)
    local results = {}

    -- Retrieve iDRAC version
    local idrac_version = get_idrac_version(host, port)
    if idrac_version then
        table.insert(results, idrac_version)
    end

    -- Retrieve firmware information
    local firmware_info = get_firmware_info(host, port)
    if firmware_info then
        table.insert(results, firmware_info)
    end

    -- Detect iDRAC 8
    local idrac8_info = detect_idrac8(host, port)
    if idrac8_info then
        table.insert(results, idrac8_info)
    end

    -- Return results only if something was found
    if #results > 0 then
        return "|_" .. table.concat(results, "\n|_")
    end
end
local utils = require "vuci.utils"
local cjson = require "cjson"

local M = {}

HOSTS_PATH = "/tmp/hosts.json"
STATUS_PATH = "/tmp/status.json"

function M.do_search(params)
    local command = nil
    if params.openPorts and params.ip and params.netmask then
        if params.from and params.to and params.from ~="" and params.to ~="" then
            command = "nethosts.lua --ip " .. params.ip .. " --netmask " .. params.netmask .. " --openports --from " .. params.from .." --to " .. params.to .." -q"
        elseif params.from and params.from ~="" then
            command = "nethosts.lua --ip " .. params.ip .. " --netmask " .. params.netmask .. " --openports --from " .. params.from .." -q"
        elseif params.to and params.to ~="" then
            command = "nethosts.lua --ip " .. params.ip .. " --netmask " .. params.netmask .. " --openports --to " .. params.to .." -q"
        else
            command = "nethosts.lua --ip " .. params.ip .. " --netmask " .. params.netmask .. " --openports  -q"
        end
    elseif params.ip and params.netmask then
        command = "nethosts.lua --ip " .. params.ip .. " --netmask " .. params.netmask .. " -q"
    else
        return { status = "error", message = "Required IP and Netmask params" }
    end
    io.popen(command)
    return { status = "ok", message = "started" }
end

function M.get_search_results(params)
    local list = nil
    local file = nil

    local status = cjson.decode(utils.readfile(STATUS_PATH))
    if status.status == "error" then
        return { status = "error", message = status.message  }
    end

    if status.message == "done" and status.status == "ok" then
        file = utils.readfile(HOSTS_PATH)
        if file then       
            list = cjson.decode(file)
            return { status = "ok", message = status.message, list =  list}
        else
            return { status = "error", message = "Search unsuccessful", list = nil }
        end
    elseif status.status == "error" then
        return { status = "error", message = status.message, list = nil }
    else
        return { status = "ok", message = status.message, list = nil  }
    end
end

return M
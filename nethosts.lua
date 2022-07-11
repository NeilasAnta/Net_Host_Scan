#! /usr/bin/env lua

local cjson = require "cjson"
local argparse = require "argparse"

HOSTS = "/tmp/hosts.json"
STATUS = "/tmp/status.json"

NetworkDatabase = {}
local AllDiscoveredHosts = { }

function runShellCommand( shellCommand, resultHandler )
    local tempFile = "lua-shell-cmd"
    if not os.execute( shellCommand.." > "..tempFile ) then
        error( "Execution of OS command '"..shellCommand.."' failed!" )
    end

    if not io.input( tempFile ) then
        error( "Cannot open file '"..tempFile..
            "' containing OS command results!" )
    end

    for line in io.lines() do
        if line:match( "%w" ) then
            resultHandler = resultHandler( line )
            if not resultHandler then break end
        end
    end

    io.input():close()
    os.remove( tempFile )
end

function ScanNetworkForHosts ( Subnet )
    local AllDiscoveredHosts = { }

    local thisSubnet = Subnet.ipv4subnet

    if not thisSubnet then
        thisSubnet = "-6 "..Subnet.ipv6subnet
    end

    local shellCommand = "nmap -n -sP "..thisSubnet

    local resultHandlerInitial
    local resultHandlerMiddle
    local resultHandlerFinal


    resultHandlerInitial = function ( line )
        local ipNumber = line:match( "Nmap scan report for (%S+)" )

        if ipNumber then
            AllDiscoveredHosts[ #AllDiscoveredHosts + 1 ] =
                { ipNumber=ipNumber}
            return resultHandlerMiddle
        end

        if not line:match( "Starting Nmap" ) then
            error( "Could not detect start of 'nmap' scan!" )
        end

        return resultHandlerInitial
    end


    resultHandlerMiddle = function ( line )
        local status = line:match( "Host is (%w+)" )

        if not status then
            error( "Network scan failed for host with IP '"..
                AllDiscoveredHosts[ #AllDiscoveredHosts ].ipNumber.."'! " )
        end
        AllDiscoveredHosts[ #AllDiscoveredHosts ].status = status

        return resultHandlerFinal
    end


    resultHandlerFinal = function ( line )
        local macAddr, vendor = line:match( "MAC Address: (%S+)%s+(.+)" )

        if macAddr then
            AllDiscoveredHosts[ #AllDiscoveredHosts ].macAddr = macAddr:upper()
            return resultHandlerInitial
        end

        if AllDiscoveredHosts[1].ipNumber and
            not AllDiscoveredHosts[1].macAddr then
                error( "NMAP is not returning MAC addresses;"..
                    " is 'sudo' working?" )
        end

        if not line:match( "Nmap done" ) then
            error( "Could not detect end of 'nmap' scan!" )
        end

    end

    runShellCommand( shellCommand, resultHandlerInitial )
    return AllDiscoveredHosts
end

function getAllMyNICs ( )
    local MyNICs = { }
    local shellCommand = "ip -br addr"

    local resultHandler

    resultHandler = function ( line )
        local deviceName, ipNumber = line:match( "(%w+)%s+UP%s+([^/]+)" )

        if deviceName then MyNICs[ #MyNICs + 1 ] =
            { deviceName=deviceName, ipNumber=ipNumber }
        end

        return resultHandler
    end

    runShellCommand( shellCommand, resultHandler )
    return MyNICs
end

function getAllMyMACs ( )
    local MyMACs = { }
    local shellCommand = "ip -o -f link addr"
    local resultHandler

    resultHandler = function ( line )
        local deviceName, macAddr = line:match( "%d+: (%w+):.+ether (%S+)" )

        if deviceName then MyMACs[ #MyMACs + 1 ] =
            { deviceName=deviceName, macAddr=macAddr:upper() }
        end

        return resultHandler
    end

    runShellCommand( shellCommand, resultHandler )
    return MyMACs
end

function myNICnameFromIPnumber ( myIPnumber )
    if not myIPnumber then
        error "Cannot resolve an interface name from a 'nil' IP number!"
    end

    for _, ThisNIC in ipairs( getAllMyNICs() ) do
        if not ThisNIC or not ThisNIC.ipNumber then
            error( "Network interface '"..ThisNIC.deviceName..
                "' has no IP number!" )
        end

        if ThisNIC.ipNumber == myIPnumber then
            if ThisNIC.deviceName then return ThisNIC.deviceName end

            error( "Network interface with IP number '"..
                ThisNIC.ipNumber.."' has no description!" )
        end
    end

    error( "Cannot find my own network interface device!" )
end

function myMACaddrFromNICname ( myNICname )
    if not myNICname then
        error "Cannot resolve a MAC address from a 'nil' interface name!"
    end

    for _, ThisMAC in ipairs( getAllMyMACs() ) do

        if not ThisMAC or not ThisMAC.deviceName then
            error( "Network interface '"..ThisMAC.macAddr..
                "' has no device name!" )
        end

        if ThisMAC.deviceName == myNICname then
            if ThisMAC.macAddr then return ThisMAC.macAddr end

            error( "Network interface '"..
                ThisMAC.deviceName.."' has no MAC address!" )
        end
    end

    error( "Cannot find my own network device's MAC address!" )
end

function getMyMacAddr ( myIPnumber )
    local myNICname = myNICnameFromIPnumber( myIPnumber )

    return myMACaddrFromNICname( myNICname )
end

function findHostsOnNetwork ( Subnet )
    local MyHost
    local subnetDescr = Subnet.description

    DiscoveredHosts = ScanNetworkForHosts( Subnet )

    if #DiscoveredHosts < 1 then
        error( "Scan of network "..subnetDescr..
            " did not return ANY hosts! " )
    end

    MyHost = DiscoveredHosts[ #DiscoveredHosts ]
    MyHost.macAddr = getMyMacAddr( MyHost.ipNumber )
    DiscoveredHosts[ #DiscoveredHosts ] = MyHost

    return DiscoveredHosts
end


function printHostReportToFile (NetworkHost )
    hosts = io.open(HOSTS, "w")
    hosts:write(cjson.encode(NetworkHost))
    hosts:close()
end

function printHostReportRecord (NetworkHost, OpenPorts )
    local ipNumberString = NetworkHost.ipNumber
    local macAddrString  = NetworkHost.macAddr
    local description    = NetworkHost.description
    local openPorts    = NetworkHost.openPorts
    local reportFormat = "host: IP number %-14s MAC addr %s %s %s"

    if description then
        description = "  descr: "..description
    else
        description = ""
    end

    if openPorts then
        openPorts = " openPorts: " .. table.concat(openPorts, ', ')
    elseif not OpenPorts then
        openPorts = " "
    else
        openPorts= " openPorts: not found"
    end
    
    print( string.format( reportFormat, ipNumberString, macAddrString, description,  openPorts) )
end

function printHostReport ( Subnet, SortedHosts, OpenPorts )

    print()

    if #SortedHosts == 0 then
        print( string.format( "No hosts found." ) )
        return
    end

    for _, ThisHost in ipairs( SortedHosts ) do

        printHostReportRecord( ThisHost, OpenPorts )
    end
end

function main ( Database, Quiet, OpenPorts, PortsFrom, PortsTo )
    for _, Subnet in ipairs( Database.Subnets ) do
        local status, err = pcall(function () AllDiscoveredHosts = findHostsOnNetwork( Subnet ) end)

        if OpenPorts then
            setOpenPorts(AllDiscoveredHosts, PortsFrom, PortsTo)
        end

        if Quiet then
            if not status then 
                printStatusToFile("error", "Not found", STATUS)
            else
                printHostReportToFile( AllDiscoveredHosts )
                printStatusToFile("ok", "done", STATUS)
            end
        else
            printHostReport( Subnet, AllDiscoveredHosts, OpenPorts)
        end

    end
end

function setOpenPorts(AllDiscoveredHosts, PortsFrom, PortsTo)
    for i, ip in ipairs( AllDiscoveredHosts ) do
        local ports = getOpenPorts(ip.ipNumber, PortsFrom, PortsTo)
        if next(ports) ~= nil then
            AllDiscoveredHosts[i].openPorts = ports
        end
    end
end

function printStatusToFile(status, message, fileName)
    printStatus = io.open(fileName, "w")
    printStatus:write(cjson.encode({
        status = status,
        message = message,
    }))
    io.close(printStatus)
end

function getOpenPorts(ip, PortsFrom, PortsTo)
    local ports = {}
    local shellCommand = "nmap -F " .. ip
    local tempFile = "nmap-response"
    
    if not os.execute( shellCommand.." > "..tempFile ) then
        error( "Execution of OS command '"..shellCommand.."' failed!" )
    end
    
    if not io.input( tempFile ) then
        error( "Cannot open file '"..tempFile..
            "' containing OS command results!" )
    end
    
    for line in io.lines() do    
        if line:match("open") then
            local openPort = tonumber(line:match( "(%d+)" ))
            if openPort >= tonumber(PortsFrom) and openPort <= tonumber(PortsTo) then
                table.insert(ports, openPort)
            end
        end
    end
    
    io.input():close()
    os.remove(tempFile)
    return ports
end

local parser = argparse()
parser:flag("--openports", "Find open ports")
parser:flag("-q --quiet", "Flag to print to file")
parser:option(" --ip", "IP address")
parser:option(" --netmask", "Netmask")
parser:option("-f --from")
parser:option("-t --to")
local args = parser:parse()

if args['from'] == nil then
    args['from'] = "0"
end

if args['to'] == nil then
    args['to'] = "65535"
end

if args["ip"] ~= nil and args["netmask"] ~= nil then
    if args['quiet'] then
        os.remove(HOSTS)
        os.remove(STATUS)
        printStatusToFile("ok", "started", STATUS) 
    end
    NetworkDatabase.Subnets = {
        {
        ipv4subnet = args["ip"] .. "/" .. args["netmask"],
        }
    }
    main( NetworkDatabase, args['quiet'], args['openports'], args['from'], args['to'])
else
    if args['quiet'] then
        printStatusToFile("error", "Required --ip and --netmask params", STATUS)
    else
        print("Required --ip and --netmask params")
    end
end

-------------------------------------------------------------------------------

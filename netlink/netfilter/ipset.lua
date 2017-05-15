--
-- Created by IntelliJ IDEA.
-- User: sskaje
-- Date: 2017/4/7
-- Time: 下午4:34
-- To change this template use File | Settings | File Templates.
--

local Netlink   = require "../netlink"
local Netfilter = require "../netfilter/netfilter"
local NFUtils   = require "../utils/misc"



local ipset = {}

local IPSET_CMD_NONE        = 0x00
local IPSET_CMD_PROTOCOL    = 0x01 
local IPSET_CMD_CREATE      = 0x02
local IPSET_CMD_DESTROY     = 0x03
local IPSET_CMD_FLUSH       = 0x04
local IPSET_CMD_RENAME      = 0x05
local IPSET_CMD_SWAP        = 0x06
local IPSET_CMD_LIST        = 0x07
local IPSET_CMD_SAVE        = 0x08
local IPSET_CMD_ADD         = 0x09
local IPSET_CMD_DEL         = 0x0A
local IPSET_CMD_TEST        = 0x0B
local IPSET_CMD_HEADER      = 0x0C
local IPSET_CMD_TYPE        = 0x0D
local IPSET_CMD_RESTORE     = 0x0E
local IPSET_CMD_HELP        = 0x0F
local IPSET_CMD_VERSION     = 0x10
local IPSET_CMD_QUIT        = 0x11
local IPSET_CMD_COMMIT      = 0x12

ipset.cmd =
{
    NONE        = IPSET_CMD_NONE,
    PROTOCOL    = IPSET_CMD_PROTOCOL,
    CREATE      = IPSET_CMD_CREATE,
    DESTROY     = IPSET_CMD_DESTROY,
    FLUSH       = IPSET_CMD_FLUSH,
    RENAME      = IPSET_CMD_RENAME,
    SWAP        = IPSET_CMD_SWAP,
    LIST        = IPSET_CMD_LIST,
    SAVE        = IPSET_CMD_SAVE,
    ADD         = IPSET_CMD_ADD,
    DEL         = IPSET_CMD_DEL,
    TEST        = IPSET_CMD_TEST,
    HEADER      = IPSET_CMD_HEADER,
    TYPE        = IPSET_CMD_TYPE,
    RESTORE     = IPSET_CMD_RESTORE,
    HELP        = IPSET_CMD_HELP,
    VERSION     = IPSET_CMD_VERSION,
    QUIT        = IPSET_CMD_QUIT,
    COMMIT      = IPSET_CMD_COMMIT
}

ipset.cmdNames =
{
    [IPSET_CMD_NONE]        = "NONE",
    [IPSET_CMD_PROTOCOL]    = "PROTOCOL",
    [IPSET_CMD_CREATE]      = "CREATE",
    [IPSET_CMD_DESTROY]     = "DESTROY",
    [IPSET_CMD_FLUSH]       = "FLUSH",
    [IPSET_CMD_RENAME]      = "RENAME",
    [IPSET_CMD_SWAP]        = "SWAP",
    [IPSET_CMD_LIST]        = "LIST",
    [IPSET_CMD_SAVE]        = "SAVE",
    [IPSET_CMD_ADD]         = "ADD",
    [IPSET_CMD_DEL]         = "DEL",
    [IPSET_CMD_TEST]        = "TEST",
    [IPSET_CMD_HEADER]      = "HEADER",
    [IPSET_CMD_TYPE]        = "TYPE",
    [IPSET_CMD_RESTORE]     = "RESTORE",
    [IPSET_CMD_HELP]        = "HELP",
    [IPSET_CMD_VERSION]     = "VERSION",
    [IPSET_CMD_QUIT]        = "QUIT",
    [IPSET_CMD_COMMIT]      = "COMMIT"
}

ipset.flags_common =
{
    [0x00] = "Request",
    [0x01] = "Multipart message",
    [0x02] = "Ack",
    [0x03] = "Echo",
    [0x04] = "Dump intr",
    [0x05] = "",
    [0x06] = "",
    [0x07] = "",
}



--[[
IPset_cmd_flags =
{
	[0]	=	"IPSET_FLAG_EXIST",
	[1]	=	"IPSET_FLAG_LIST_SETNAME",
	[2]	=	"IPSET_FLAG_LIST_HEADER",
	[3]	=	"IPSET_FLAG_SKIP_COUNTER_UPDATE",
	[4]	=	"IPSET_FLAG_SKIP_SUBCOUNTER_UPDATE",
	[5]	=	"IPSET_FLAG_MATCH_COUNTERS",
	[6]	=	"",
	[7]	=	"IPSET_FLAG_RETURN_NOMATCH",
	[8]	=	"IPSET_FLAG_MAP_SKBMARK",
	[9]	=	"IPSET_FLAG_MAP_SKBPRIO",
	[10]	=	"IPSET_FLAG_MAP_SKBQUEUE",
	[11]	=	"",
	[12]	=	"",
	[13]	=	"",
	[14]	=	"",
	[15]	=	"IPSET_FLAG_CMD_MAX",
}
]] --

-- CADT specific attributes
local IPSET_ATTR_IP_FROM    = 1
local IPSET_ATTR_IP_TO      = 2
local IPSET_ATTR_CIDR       = 3
local IPSET_ATTR_PORT       = 4
local IPSET_ATTR_PORT_TO    = 5
local IPSET_ATTR_TIMEOUT    = 6
local IPSET_ATTR_PROTO      = 7
local IPSET_ATTR_CADT_FLAGS = 8
local IPSET_ATTR_LINENO     = 9
local IPSET_ATTR_MARK       = 10
local IPSET_ATTR_MARKMASK   = 11

local IPSET_ATTR_CADT_MAX   = 16

-- Create-only specific attributes
local IPSET_ATTR_GC         = 17
local IPSET_ATTR_HASHSIZE   = 18
local IPSET_ATTR_MAXELEM    = 19
local IPSET_ATTR_NETMASK    = 20
local IPSET_ATTR_PROBES     = 21
local IPSET_ATTR_RESIZE     = 22
local IPSET_ATTR_SIZE       = 23
-- Kernel-only
local IPSET_ATTR_ELEMENTS   = 24
local IPSET_ATTR_REFERENCES = 25
local IPSET_ATTR_MEMSIZE    = 26
local IPSET_ATTR_CREATE_MAX = 26

-- ADT specific attributes
local IPSET_ATTR_ETHER      = 17
local IPSET_ATTR_NAME       = 18
local IPSET_ATTR_NAMEREF    = 19
local IPSET_ATTR_IP2        = 20
local IPSET_ATTR_CIDR2      = 21
local IPSET_ATTR_IP2_TO     = 22
local IPSET_ATTR_IFACE      = 23
local IPSET_ATTR_BYTES      = 24
local IPSET_ATTR_PACKETS    = 25
local IPSET_ATTR_COMMENT    = 26
local IPSET_ATTR_SKBMARK    = 27
local IPSET_ATTR_SKBPRIO    = 28
local IPSET_ATTR_SKBQUEUE   = 29
local IPSET_ATTR_ADT_MAX    = 29

local IPSET_ATTR_IPADDR_IPV4 = 1
local IPSET_ATTR_IPADDR_IPV6 = 2
local IPSET_ATTR_IPADDR_MAX  = 2

ipset.Attr = 
{
    IP_FROM     = IPSET_ATTR_IP_FROM,
    IP_TO       = IPSET_ATTR_IP_TO,
    CIDR        = IPSET_ATTR_CIDR,
    PORT        = IPSET_ATTR_PORT,
    PORT_TO     = IPSET_ATTR_PORT_TO,
    TIMEOUT     = IPSET_ATTR_TIMEOUT,
    PROTO       = IPSET_ATTR_PROTO,
    CADT_FLAGS  = IPSET_ATTR_CADT_FLAGS,
    LINENO      = IPSET_ATTR_LINENO,
    MARK        = IPSET_ATTR_MARK,
    MARKMASK    = IPSET_ATTR_MARKMASK,
    CADT_MAX    = IPSET_ATTR_CADT_MAX,
    GC          = IPSET_ATTR_GC,
    HASHSIZE    = IPSET_ATTR_HASHSIZE,
    MAXELEM     = IPSET_ATTR_MAXELEM,
    NETMASK     = IPSET_ATTR_NETMASK,
    PROBES      = IPSET_ATTR_PROBES,
    RESIZE      = IPSET_ATTR_RESIZE,
    SIZE        = IPSET_ATTR_SIZE,
    ELEMENTS    = IPSET_ATTR_ELEMENTS,
    REFERENCES  = IPSET_ATTR_REFERENCES,
    MEMSIZE     = IPSET_ATTR_MEMSIZE,
    ETHER       = IPSET_ATTR_ETHER,
    NAME        = IPSET_ATTR_NAME,
    NAMEREF     = IPSET_ATTR_NAMEREF,
    IP2         = IPSET_ATTR_IP2,
    CIDR2       = IPSET_ATTR_CIDR2,
    IP2_TO      = IPSET_ATTR_IP2_TO,
    IFACE       = IPSET_ATTR_IFACE,
    BYTES       = IPSET_ATTR_BYTES,
    PACKETS     = IPSET_ATTR_PACKETS,
    COMMENT     = IPSET_ATTR_COMMENT,
    SKBMARK     = IPSET_ATTR_SKBMARK,
    SKBPRIO     = IPSET_ATTR_SKBPRIO,
    SKBQUEUE    = IPSET_ATTR_SKBQUEUE
}

ipset.AttrNames =
{
    [0]                     =   "UNSPEC",
    [IPSET_ATTR_IP_FROM]	=	"IP/IP_FROM",
    [IPSET_ATTR_IP_TO]	    =	"IP_TO",
    [IPSET_ATTR_CIDR]	    =	"CIDR",
    [IPSET_ATTR_PORT]	    =	"PORT",
    [IPSET_ATTR_PORT_TO]	=	"PORT_TO",
    [IPSET_ATTR_TIMEOUT]	=	"TIMEOUT",
    [IPSET_ATTR_PROTO]	    =	"PROTO",
    [IPSET_ATTR_CADT_FLAGS]	=	"CADT_FLAGS",
    [IPSET_ATTR_LINENO]	    =	"LINENO",
    [IPSET_ATTR_MARK]	    =	"MARK",
    [IPSET_ATTR_MARKMASK]	=	"MARKMASK",
    [IPSET_ATTR_CADT_MAX]	=	"CADT_MAX",
    [IPSET_ATTR_GC]	        =	"GC",
    [IPSET_ATTR_HASHSIZE]	=	"HASHSIZE",
    [IPSET_ATTR_MAXELEM]	=	"MAXELEM",
    [IPSET_ATTR_NETMASK]	=	"NETMASK",
    [IPSET_ATTR_PROBES]     =	"PROBES",
    [IPSET_ATTR_RESIZE]     =	"RESIZE",
    [IPSET_ATTR_SIZE]       =	"SIZE",
    [IPSET_ATTR_ELEMENTS]	=	"ELEMENTS",
    [IPSET_ATTR_REFERENCES]	=	"REFERENCES",
    [IPSET_ATTR_MEMSIZE]	=	"MEMSIZE",
    [IPSET_ATTR_ETHER]	    =	"ETHER",
    [IPSET_ATTR_NAME]	    =	"NAME",
    [IPSET_ATTR_NAMEREF]	=	"NAMEREF",
    [IPSET_ATTR_IP2]	    =	"IP2",
    [IPSET_ATTR_CIDR2]	    =	"CIDR2",
    [IPSET_ATTR_IP2_TO]	    =	"IP2_TO",
    [IPSET_ATTR_IFACE]	    =	"IFACE",
    [IPSET_ATTR_BYTES]	    =	"BYTES",
    [IPSET_ATTR_PACKETS]	=	"PACKETS",
    [IPSET_ATTR_COMMENT]	=	"COMMENT",
    [IPSET_ATTR_SKBMARK]	=	"SKBMARK",
    [IPSET_ATTR_SKBPRIO]	=	"SKBPRIO",
    [IPSET_ATTR_SKBQUEUE]	=	"SKBQUEUE"
}

local CADTAttributes = {
    [IPSET_ATTR_IP_FROM]	=	IPSET_ATTR_IP_FROM,
    [IPSET_ATTR_IP_TO]	    =	IPSET_ATTR_IP_TO,
    [IPSET_ATTR_CIDR]	    =	IPSET_ATTR_CIDR,
    [IPSET_ATTR_PORT]	    =	IPSET_ATTR_PORT,
    [IPSET_ATTR_PORT_TO]	=	IPSET_ATTR_PORT_TO,
    [IPSET_ATTR_TIMEOUT]	=	IPSET_ATTR_TIMEOUT,
    [IPSET_ATTR_PROTO]	    =	IPSET_ATTR_PROTO,
    [IPSET_ATTR_CADT_FLAGS]	=	IPSET_ATTR_CADT_FLAGS,
    [IPSET_ATTR_LINENO]	    =	IPSET_ATTR_LINENO,
    [IPSET_ATTR_MARK]	    =	IPSET_ATTR_MARK,
    [IPSET_ATTR_MARKMASK]	=	IPSET_ATTR_MARKMASK,

    [IPSET_ATTR_GC]	        =	IPSET_ATTR_GC,
    [IPSET_ATTR_HASHSIZE]	=	IPSET_ATTR_HASHSIZE,
    [IPSET_ATTR_MAXELEM]	=	IPSET_ATTR_MAXELEM,
    [IPSET_ATTR_NETMASK]	=	IPSET_ATTR_NETMASK,
    [IPSET_ATTR_PROBES]     =	IPSET_ATTR_PROBES,
    [IPSET_ATTR_RESIZE]     =	IPSET_ATTR_RESIZE,
    [IPSET_ATTR_SIZE]       =	IPSET_ATTR_SIZE,
    [IPSET_ATTR_ELEMENTS]	=	IPSET_ATTR_ELEMENTS,
    [IPSET_ATTR_REFERENCES]	=	IPSET_ATTR_REFERENCES,
    [IPSET_ATTR_MEMSIZE]	=	IPSET_ATTR_MEMSIZE,
}

local ADTAttributes = {
    [IPSET_ATTR_IP_FROM]	=	IPSET_ATTR_IP_FROM,
    [IPSET_ATTR_IP_TO]	    =	IPSET_ATTR_IP_TO,
    [IPSET_ATTR_CIDR]	    =	IPSET_ATTR_CIDR,
    [IPSET_ATTR_PORT]	    =	IPSET_ATTR_PORT,
    [IPSET_ATTR_PORT_TO]	=	IPSET_ATTR_PORT_TO,
    [IPSET_ATTR_TIMEOUT]	=	IPSET_ATTR_TIMEOUT,
    [IPSET_ATTR_PROTO]	    =	IPSET_ATTR_PROTO,
    [IPSET_ATTR_CADT_FLAGS]	=	IPSET_ATTR_CADT_FLAGS,
    [IPSET_ATTR_LINENO]	    =	IPSET_ATTR_LINENO,
    [IPSET_ATTR_MARK]	    =	IPSET_ATTR_MARK,
    [IPSET_ATTR_MARKMASK]	=	IPSET_ATTR_MARKMASK,
    
    [IPSET_ATTR_ETHER]	    =	IPSET_ATTR_ETHER,
    [IPSET_ATTR_NAME]	    =	IPSET_ATTR_NAME,
    [IPSET_ATTR_NAMEREF]	=	IPSET_ATTR_NAMEREF,
    [IPSET_ATTR_IP2]	    =	IPSET_ATTR_IP2,
    [IPSET_ATTR_CIDR2]	    =	IPSET_ATTR_CIDR2,
    [IPSET_ATTR_IP2_TO]	    =	IPSET_ATTR_IP2_TO,
    [IPSET_ATTR_IFACE]	    =	IPSET_ATTR_IFACE,
    [IPSET_ATTR_BYTES]	    =	IPSET_ATTR_BYTES,
    [IPSET_ATTR_PACKETS]	=	IPSET_ATTR_PACKETS,
    [IPSET_ATTR_COMMENT]	=	IPSET_ATTR_COMMENT,
    [IPSET_ATTR_SKBMARK]	=	IPSET_ATTR_SKBMARK,
    [IPSET_ATTR_SKBPRIO]	=	IPSET_ATTR_SKBPRIO,
    [IPSET_ATTR_SKBQUEUE]	=	IPSET_ATTR_SKBQUEUE
}


local IPSET_ERR_PRIVATE             = 4096
local IPSET_ERR_PROTOCOL            = 4097
local IPSET_ERR_FIND_TYPE           = 4098
local IPSET_ERR_MAX_SETS            = 4099
local IPSET_ERR_BUSY                = 4100
local IPSET_ERR_EXIST_SETNAME2      = 4101
local IPSET_ERR_TYPE_MISMATCH       = 4102
local IPSET_ERR_EXIST               = 4103
local IPSET_ERR_INVALID_CIDR        = 4104
local IPSET_ERR_INVALID_NETMASK     = 4105
local IPSET_ERR_INVALID_FAMILY      = 4106
local IPSET_ERR_TIMEOUT             = 4107
local IPSET_ERR_REFERENCED          = 4108
local IPSET_ERR_IPADDR_IPV4         = 4109
local IPSET_ERR_IPADDR_IPV6         = 4110
local IPSET_ERR_COUNTER             = 4111
local IPSET_ERR_COMMENT             = 4112
local IPSET_ERR_INVALID_MARKMASK    = 4113
local IPSET_ERR_SKBINFO             = 4114
local IPSET_ERR_TYPE_SPECIFIC       = 4352

ipset.ErrorCodes = 
{
    PRIVATE             = IPSET_ERR_PRIVATE           ,
    PROTOCOL            = IPSET_ERR_PROTOCOL          ,
    FIND_TYPE           = IPSET_ERR_FIND_TYPE         ,
    MAX_SETS            = IPSET_ERR_MAX_SETS          ,
    BUSY                = IPSET_ERR_BUSY              ,
    EXIST_SETNAME2      = IPSET_ERR_EXIST_SETNAME2    ,
    TYPE_MISMATCH       = IPSET_ERR_TYPE_MISMATCH     ,
    EXIST               = IPSET_ERR_EXIST             ,
    INVALID_CIDR        = IPSET_ERR_INVALID_CIDR      ,
    INVALID_NETMASK     = IPSET_ERR_INVALID_NETMASK   ,
    INVALID_FAMILY      = IPSET_ERR_INVALID_FAMILY    ,
    TIMEOUT             = IPSET_ERR_TIMEOUT           ,
    REFERENCED          = IPSET_ERR_REFERENCED        ,
    IPADDR_IPV4         = IPSET_ERR_IPADDR_IPV4       ,
    IPADDR_IPV6         = IPSET_ERR_IPADDR_IPV6       ,
    COUNTER             = IPSET_ERR_COUNTER           ,
    COMMENT             = IPSET_ERR_COMMENT           ,
    INVALID_MARKMASK    = IPSET_ERR_INVALID_MARKMASK  ,
    SKBINFO             = IPSET_ERR_SKBINFO           ,
    TYPE_SPECIFIC       = IPSET_ERR_TYPE_SPECIFIC     
}

ipset.ErrorMessages =
{
    [IPSET_ERR_PRIVATE]          = "PRIVATE"          ,
    [IPSET_ERR_PROTOCOL]         = "PROTOCOL"         ,
    [IPSET_ERR_FIND_TYPE]        = "FIND_TYPE"        ,
    [IPSET_ERR_MAX_SETS]         = "MAX_SETS"         ,
    [IPSET_ERR_BUSY]             = "BUSY"             ,
    [IPSET_ERR_EXIST_SETNAME2]   = "EXIST_SETNAME2"   ,
    [IPSET_ERR_TYPE_MISMATCH]    = "TYPE_MISMATCH"    ,
    [IPSET_ERR_EXIST]            = "EXIST"            ,
    [IPSET_ERR_INVALID_CIDR]     = "INVALID_CIDR"     ,
    [IPSET_ERR_INVALID_NETMASK]  = "INVALID_NETMASK"  ,
    [IPSET_ERR_INVALID_FAMILY]   = "INVALID_FAMILY"   ,
    [IPSET_ERR_TIMEOUT]          = "TIMEOUT"          ,
    [IPSET_ERR_REFERENCED]       = "REFERENCED"       ,
    [IPSET_ERR_IPADDR_IPV4]      = "IPADDR_IPV4"      ,
    [IPSET_ERR_IPADDR_IPV6]      = "IPADDR_IPV6"      ,
    [IPSET_ERR_COUNTER]          = "COUNTER"          ,
    [IPSET_ERR_COMMENT]          = "COMMENT"          ,
    [IPSET_ERR_INVALID_MARKMASK] = "INVALID_MARKMASK" ,
    [IPSET_ERR_SKBINFO]          = "SKBINFO"          ,
    [IPSET_ERR_TYPE_SPECIFIC]    = "TYPE_SPECIFIC"
}

ipset.errorMessage = function(code)
    code = 0 - code
    if ipset.ErrorMessages[code] then
        return ipset.ErrorMessages[code]
    else
        return "UNKNOWN"
    end
end


ipset.cmd_flags =
{
    [0x00] = "UNSPEC",
    [0x01] = "PROTOCOL",
    [0x02] = "SETNAME",
    [0x03] = "TYPENAME",
    [0x04] = "REVISION",
    [0x05] = "FAMILY",
    [0x06] = "FLAGS",
    [0x07] = "DATA",
    [0x08] = "ADT",
    [0x09] = "LINENO",
    [0x0A] = "PROTOCOL_MIN"
}


ipset.is_get_request = function(cmd)
    if cmd == 0x07 then
        return 1
    else
        return 0
    end
end

ipset.get_command_flags = function(cmd)
    if ipset.is_get_request(cmd) == 1 then
        return ipset.flags_get
    else
        return ipset.flags_new
    end
end


local function processSegment(data_tree, tvbrange)
    local length = NFUtils.extract.uint16(tvbrange, 0)
    local type   = NFUtils.extract.uint16(tvbrange, 2)
    local is_nested = Netlink.isNested(type)
    local is_net_byteorder = Netlink.isNetByteOrder(type)
    local attribute = Netlink.getAttribute(type)

    data_tree:add(tvbrange(0, 2), "Length: " .. length)
    local type_tree = data_tree:add(tvbrange(2, 2), "Type: " .. string.format("%04x", type))
    if is_nested then
        type_tree:add(tvbrange(2, 2), "Nested: true")
    else
        type_tree:add(tvbrange(2, 2), "Nested: false")
    end

    if is_net_byteorder then
        type_tree:add(tvbrange(2, 2), "Net ByteOrder: true")
    else
        type_tree:add(tvbrange(2, 2), "Net ByteOrder: false")
    end

    type_tree:add(tvbrange(2, 2), "Attribute: " .. attribute)

    if ADTAttributes[attribute] then
        type_tree:add(tvbrange(2, 2), "AttributeName: " .. ipset.AttrNames[attribute])
    end

    local current_pos = 0

    if is_nested then
        current_pos = current_pos + 4
        local length_left = length - 4

        local nested_tree = data_tree:add(tvbrange(current_pos, length_left), "Nested data")

        local index = 0
        while length_left > 0 do
            local seg_length = NFUtils.extract.uint16(tvbrange, current_pos)
            local index_tree = nested_tree:add(tvbrange(current_pos, seg_length), "Index["..index.."]")

            processSegment(index_tree, tvbrange(current_pos, seg_length))

            current_pos = current_pos + Netlink.NLA_ALIGN(seg_length)
            length_left = length_left - Netlink.NLA_ALIGN(seg_length)
            index = index + 1

        end
    else
--        data_tree:add("")

        if attribute == IPSET_ATTR_TIMEOUT or attribute == IPSET_ATTR_LINENO
            or attribute == IPSET_ATTR_NAME or attribute == IPSET_ATTR_NAMEREF
            or attribute == IPSET_ATTR_PACKETS or attribute == IPSET_ATTR_COMMENT
        then
            data_tree:add(
                tvbrange(current_pos + 4, 4),
                ipset.AttrNames[attribute].."=" .. NFUtils.extract.buint32(is_net_byteorder, tvbrange, current_pos + 4)
            )
        elseif attribute == IPSET_ATTR_IP_FROM or attribute == IPSET_ATTR_IP_TO then
            data_tree:add(
                tvbrange(current_pos+4, 4),
                ipset.AttrNames[attribute] .. "=" .. NFUtils.extract.ipv4(tvbrange, current_pos+4)
            )
        elseif attribute == IPSET_ATTR_CIDR then
            data_tree:add(
                tvbrange(current_pos+4, 1),
                ipset.AttrNames[attribute] .. "=" .. NFUtils.extract.buint8(is_net_byteorder, tvbrange, current_pos+4)
            )
        end



    end

end

--
--
--
ipset.dataSwitch =
{
    [1] = function(data, seg_tree, tvbrange)
        local pp = data:uint()
        if pp == Netfilter.Subsys.IPSET then
            seg_tree:add(tvbrange, "Protocol: " .. Netfilter.SubsysNames[pp])
        end
    end,
    [2] = function(data, seg_tree, tvbrange)
        local pp = data:string()
        seg_tree:add(tvbrange, "Set name: " .. pp);
    end,
    [3] = function(data, seg_tree, tvbrange)
        local pp = data:string()
        seg_tree:add(tvbrange, "Type name: " .. pp);
    end,
    [4] = function(data, seg_tree, tvbrange)
        local pp = data:uint()
        seg_tree:add(tvbrange, "Revision: " .. pp)
    end,
    [5] = function(data, seg_tree, tvbrange)
        local pp = data:uint()
        if pp == 2 then
            seg_tree:add(tvbrange, "Address Family: AF_INET")
        elseif pp == 30 then
            seg_tree:add(tvbrange, "Address Family: AF_INET6")
        end
    end,
    [7] = function(data, seg_tree, tvbrange)
        -- seg_tree:add(tvbrange, "length: " .. tvbrange:len())
        local nested_data_length = tvbrange:len()
        local length_left = nested_data_length
        local current_pos = 0
        local index = 0
        local data_tree
        while length_left > 0 do
            local seg_length = NFUtils.extract.uint16(tvbrange, current_pos)

            data_tree = seg_tree:add(tvbrange(current_pos, seg_length), "DATA[" .. index .. "]")

            processSegment(data_tree, tvbrange(current_pos, seg_length))

            length_left = length_left - Netlink.NLA_ALIGN(seg_length)
            current_pos = current_pos + Netlink.NLA_ALIGN(seg_length)
            index = index + 1
        end
    end,
    [8] = function(data, seg_tree, tvbrange)
        -- seg_tree:add(tvbrange, "length: " .. tvbrange:len())
        local nested_data_length = tvbrange:len()
        local length_left = nested_data_length
        local current_pos = 0
        local index = 0
        local data_tree
        while length_left > 0 do
            local seg_length = NFUtils.extract.uint16(tvbrange, current_pos)

            data_tree = seg_tree:add(tvbrange(current_pos, seg_length), "ADT[" .. index .. "]")

            processSegment(data_tree, tvbrange(current_pos, seg_length))

            length_left = length_left - Netlink.NLA_ALIGN(seg_length)
            current_pos = current_pos + Netlink.NLA_ALIGN(seg_length)
            index = index + 1
        end
    end
}

return ipset
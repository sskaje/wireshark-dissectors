
local netlink = {}


local NLMSG_NOOP    = 0x01
local NLMSG_ERROR   = 0x02
local NLMSG_DONE    = 0x03
local NLMSG_OVERRUN = 0x04


netlink.Control =
{
    NOOP    = NLMSG_NOOP,
    ERROR   = NLMSG_ERROR,
    DONE    = NLMSG_DONE,
    OVERRUN = NLMSG_OVERRUN
}

netlink.ControlNames =
{
    [NLMSG_NOOP]      =   'NOOP (Nothing.)',
    [NLMSG_ERROR]     =   'ERROR (Error)',
    [NLMSG_DONE]      =   'DONE (End of a dump)',
    [NLMSG_OVERRUN]   =   'OVERRUN (Data lost)'
}



netlink.flags_get =
{
    [0x00] = "Request",
    [0x01] = "Multipart message",
    [0x02] = "Ack",
    [0x03] = "Echo",
    [0x04] = "Dump intr",
    [0x05] = "",
    [0x06] = "",
    [0x07] = "",
    [0x08] = "Root",
    [0x09] = "Match",
    [0x0A] = "Atomic",
    [0x0B] = "",
    [0x0C] = "",
    [0x0D] = "",
    [0x0E] = "",
    [0x0F] = ""
}

netlink.flags_new =
{
    [0x00] = "Request",
    [0x01] = "Multipart message",
    [0x02] = "Ack",
    [0x03] = "Echo",
    [0x04] = "Dump intr",
    [0x05] = "",
    [0x06] = "",
    [0x07] = "",
    [0x08] = "Replace",
    [0x09] = "Excl",
    [0x0A] = "Create",
    [0x0B] = "Append",
    [0x0C] = "",
    [0x0D] = "",
    [0x0E] = "",
    [0x0F] = ""
}

netlink.get_flags = function(is_get_request)
    if is_get_request == 1 then
        return netlink.flags_get
    else
        return netlink.flags_new
    end
end

--[[
struct nlmsghdr
{
  __u32 nlmsg_len;   /* Length of message */
  __u16 nlmsg_type;  /* Message type*/
  __u16 nlmsg_flags; /* Additional flags */
  __u32 nlmsg_seq;   /* Sequence number */
  __u32 nlmsg_pid;   /* Sending process PID */
};
 ]]

netlink.nlmsghdr =
{
    length = 0,
    type   = 0,
    flags  = 0,
    seq_no = 0,
    pid    = 0
}



local NLA_ALIGNTO = 4
netlink.NLA_ALIGN = function(len)
    return bit.band(len + NLA_ALIGNTO - 1, bit.bnot(NLA_ALIGNTO - 1))
end


--[[
    nla_type (16 bits)
    +---+---+-------------------------------+
    | N | O | Attribute Type                |
    +---+---+-------------------------------+
    N := Carries nested attributes
    O := Payload stored in network byte order

    Note: The N and O flag are mutually exclusive.
--]]
local NLA_F_NESTED         = bit.lshift(0x01, 15)
local NLA_F_NET_BYTEORDER  = bit.lshift(0x01, 14)
local NLA_TYPE_MASK        = bit.bnot(bit.bor(NLA_F_NESTED, NLA_F_NET_BYTEORDER))

netlink.isNested = function(type)
    return bit.band(type, NLA_F_NESTED) > 0
end

netlink.isNetByteOrder = function(type)
    return bit.band(type, NLA_F_NET_BYTEORDER) > 0
end

netlink.getAttribute = function(type)
    return bit.band(type, NLA_TYPE_MASK, 0xffff)
end

return netlink
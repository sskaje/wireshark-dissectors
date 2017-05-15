
local netfilter = {}

local NFNL_SUBSYS_NONE              =  0
local NFNL_SUBSYS_CTNETLINK         =  1
local NFNL_SUBSYS_CTNETLINK_EXP     =  2
local NFNL_SUBSYS_QUEUE             =  3
local NFNL_SUBSYS_ULOG              =  4
local NFNL_SUBSYS_OSF               =  5
local NFNL_SUBSYS_IPSET             =  6
local NFNL_SUBSYS_ACCT              =  7
local NFNL_SUBSYS_CTNETLINK_TIMEOUT =  8
local NFNL_SUBSYS_CTHELPER          =  9
local NFNL_SUBSYS_NFTABLES          =  10
local NFNL_SUBSYS_NFT_COMPAT        =  11
local NFNL_SUBSYS_COUNT             =  12

netfilter.Subsys =
{
    NONE              = NFNL_SUBSYS_NONE,
    CTNETLINK         = NFNL_SUBSYS_CTNETLINK,
    CTNETLINK_EXP     = NFNL_SUBSYS_CTNETLINK_EXP,
    QUEUE             = NFNL_SUBSYS_QUEUE,
    ULOG              = NFNL_SUBSYS_ULOG,
    OSF               = NFNL_SUBSYS_OSF,
    IPSET             = NFNL_SUBSYS_IPSET,
    ACCT              = NFNL_SUBSYS_ACCT,
    CTNETLINK_TIMEOUT = NFNL_SUBSYS_CTNETLINK_TIMEOUT,
    CTHELPER          = NFNL_SUBSYS_CTHELPER,
    NFTABLES          = NFNL_SUBSYS_NFTABLES,
    NFT_COMPAT        = NFNL_SUBSYS_NFT_COMPAT,
    COUNT             = NFNL_SUBSYS_COUNT
}

netfilter.SubsysNames =
{
    [NFNL_SUBSYS_NONE]              = "NONE",
    [NFNL_SUBSYS_CTNETLINK]         = "CTNETLINK",
    [NFNL_SUBSYS_CTNETLINK_EXP]     = "CTNETLINK_EXP",
    [NFNL_SUBSYS_QUEUE]             = "QUEUE",
    [NFNL_SUBSYS_ULOG]              = "ULOG",
    [NFNL_SUBSYS_OSF]               = "OSF",
    [NFNL_SUBSYS_IPSET]             = "IPSET",
    [NFNL_SUBSYS_ACCT]              = "ACCT",
    [NFNL_SUBSYS_CTNETLINK_TIMEOUT] = "CTNETLINK_TIMEOUT",
    [NFNL_SUBSYS_CTHELPER]          = "CTHELPER",
    [NFNL_SUBSYS_NFTABLES]          = "NFTABLES",
    [NFNL_SUBSYS_NFT_COMPAT]        = "NFT_COMPAT",
    [NFNL_SUBSYS_COUNT]             = "COUNT"
}



netfilter.get_subsys_from_type = function(header_type)
    return bit.rshift(header_type, 8)
end


netfilter.nfgenmsg =
{
    nfgen_family = 0,
    version      = 0,
    res_id       = 0
}

return netfilter


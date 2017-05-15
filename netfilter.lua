--[[
    Wireshark Dissector - Netfilter(IPset)

    Author: sskaje

 ]] --

package.prepend_path("netlink")

local NFUtils   = require "utils/misc"

local Netlink   = require "netlink"

local Netfilter = require "netfilter/netfilter"

local NFIPset   = require "netfilter/ipset"



local p_netfilter = Proto("netfilter", "Netlink netfilter")


p_netfilter.dissector = function(buffer, pinfo, tree)
    -- only process netfilter packet
    if buffer(2, 2):uint() ~= 0x0338 or buffer(14, 2):uint() ~= 0x0c then
        return
    end

    -- netfilter
    local nlmsghdr = Netlink.nlmsghdr

    nlmsghdr.length = NFUtils.extract.uint32(buffer, 16)
    nlmsghdr.type   = NFUtils.extract.uint16(buffer, 20)
    nlmsghdr.flags  = NFUtils.extract.uint16(buffer, 22)
    nlmsghdr.seq_no = NFUtils.extract.uint32(buffer, 24)
    nlmsghdr.pid    = NFUtils.extract.uint32(buffer, 28)

    -- new tree
    local nf_tree = tree:add(p_netfilter)

    -- netfilter header
    local nfhdr_tree = nf_tree:add(buffer(16, 16), "Netfilter HEADER")

    -- netfilter header: type
    local hdr_type_tree = nfhdr_tree:add(buffer(20, 2), "Type: " .. string.format("%04x", nlmsghdr.type))

    local nf_subsys = Netfilter.get_subsys_from_type(nlmsghdr.type)

    if nf_subsys == 0x00 then
        -- control message

        -- 0x0002: error

        hdr_type_tree:append_text(" " .. Netlink.ControlNames[nlmsghdr.type])
        pinfo.cols.protocol:append(" Control Message")

    elseif Netfilter.SubsysNames[nf_subsys] then
        hdr_type_tree:add(buffer(20, 2), "Type: " .. Netfilter.SubsysNames[nf_subsys])
        nf_tree:append_text(" ("..Netfilter.SubsysNames[nf_subsys]..")")
        pinfo.cols.protocol:append(" " .. Netfilter.SubsysNames[nf_subsys])
    else
        return
    end

    local is_get_request = 0

    if nf_subsys == Netfilter.Subsys.IPSET then
        local ipset_cmd = bit.band(nlmsghdr.type, 0x00ff)

        if type(NFIPset.cmdNames[ipset_cmd]) ~= nil then
            hdr_type_tree:add(buffer(20, 2), "Command: " .. NFIPset.cmdNames[ipset_cmd] .. "[" .. string.format("%02x", ipset_cmd) .. "]")
        else
            hdr_type_tree:add(buffer(20, 2), "Unknown comand")
        end

        is_get_request = NFIPset.is_get_request(ipset_cmd)
    else
--        return
    end

    -- netfilter header: flags
    local nfhdr_flag_tree = nfhdr_tree:add(buffer(22, 2), "Flags: " .. string.format("%04x", nlmsghdr.flags))

    nfhdr_tree:add(buffer(24, 4), "Sequence: " .. NFUtils.extract.uint32(buffer(24, 4)))
    nfhdr_tree:add(buffer(28, 4), "Pid: " .. NFUtils.extract.uint32(buffer(28, 4)))


    local flags = Netlink.get_flags(is_get_request)

    for index = 0, #flags - 1 do
        if flags[index] ~= "" then
            local dots = ""
            for dot = #flags, 0, -1 do
                if dot ~= index then
                    dots = dots .. "."
                else
                    dots = dots .. string.format("%d", bit.band(bit.rshift(nlmsghdr.flags, index), 0x01))
                end

                if dot % 4 == 0 then
                    dots = dots .. " "
                end
            end

            nfhdr_flag_tree:add(buffer(22, 2), dots .. " " .. flags[index])
        end
    end

    if bit.band(nlmsghdr.flags, 0x01) == 1 then
        pinfo.cols.src = "Client"
        pinfo.cols.dst = "System"
    else
        pinfo.cols.src = "System"
        pinfo.cols.dst = "Client"
    end


    -- Error handling
    if nlmsghdr.type == Netlink.Control.ERROR then
        local error_code = NFUtils.extract.int32(buffer, 32)
        local nferr_tree = nf_tree:add(buffer(32), "Netfilter Error")
        nferr_tree:add(buffer(32, 4), "Error code: " .. error_code)
        nferr_tree:add(buffer(32, 4), "Error Message: " .. NFIPset.errorMessage(error_code))


        return
    end


    -- data
    local nfdat_tree = nf_tree:add(buffer(32), "Netfilter DATA")

    local nfgenmsg = Netfilter.nfgenmsg

    -- nfgenmsg
    nfgenmsg.nfgen_family = buffer(32, 1):uint()
    nfgenmsg.version = buffer(33, 1):uint()
    nfgenmsg.res_id = NFUtils.extract.uint16(buffer, 34)

    local nfgenmsg_tree = nfdat_tree:add(buffer(32, 4), "nfgenmsg")
    nfgenmsg_tree:add(buffer(32, 1), "Address family: " .. nfgenmsg.nfgen_family)
    nfgenmsg_tree:add(buffer(33, 1), "Version: " .. nfgenmsg.version)
    nfgenmsg_tree:add(buffer(34, 2), "Res id: " .. nfgenmsg.res_id)

    local length_left = nlmsghdr.length - 16 - 4
    local current_pos = 36

    if buffer:len() <= current_pos then
        return
    end

    local seg_length
    local seg_flags
    local seg_data
    local seg_padding_length = 0

    local nfdataseg_tree = nfdat_tree:add(buffer(current_pos), "DATA")

    local index = 0
    while length_left > 0 do
        seg_length = NFUtils.extract.uint16(buffer, current_pos)
        current_pos = current_pos + 2

        seg_flags = NFUtils.extract.uint16(buffer, current_pos)
        current_pos = current_pos + 2

        seg_data = buffer(current_pos, seg_length - 4)

        -- padding length
        seg_padding_length = Netlink.NLA_ALIGN(seg_length) - seg_length

        local seg_tree = nfdataseg_tree:add(buffer(current_pos - 4, seg_padding_length + seg_length), "DATA[" .. index .. "]")
        seg_tree:add(buffer(current_pos - 4, 2), "Length: " .. seg_length)

        local seg_flag_tree = seg_tree:add(buffer(current_pos - 2, 2), "Flag: " .. string.format("%04x", seg_flags))

        if nf_subsys == Netfilter.Subsys.IPSET then
            local cmdflag = bit.band(seg_flags, 0xff)

            if (NFIPset.cmd_flags[cmdflag]) then
                seg_flag_tree:add(buffer(current_pos - 2, 1), "Type: " .. NFIPset.cmd_flags[cmdflag])
                if (NFIPset.dataSwitch[cmdflag]) then
                    NFIPset.dataSwitch[cmdflag](seg_data, seg_tree, buffer(current_pos, seg_length - 4))
                end
            end
        end

        current_pos = current_pos + seg_length - 4 + seg_padding_length

        length_left = length_left - seg_length - seg_padding_length
        index = index + 1
    end
end

-- register post dissector
register_postdissector(p_netfilter)

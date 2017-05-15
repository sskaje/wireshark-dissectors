--
--
--

local utils = {
    sys_little_endianness = string.dump(function() end):byte(7),
    -- data extractor by byte order
    extract = {},
    array = {},
    debug = {}
}
-- data extractor by byte order
utils.extract.uint = function(buffer, pos, bytes)
    if utils.sys_little_endianness == 1 then
        return buffer(pos, bytes):le_uint()
    else
        return buffer(pos, bytes):uint()
    end
end

-- data extractor by byte order
utils.extract.int = function(buffer, pos, bytes)
    if utils.sys_little_endianness == 1 then
        return buffer(pos, bytes):le_int()
    else
        return buffer(pos, bytes):int()
    end
end


utils.extract.buint = function(netByteOrder, buffer, pos, bytes)
    if netByteOrder then
        return buffer(pos, bytes):uint()
    else
        return buffer(pos, bytes):le_uint()
    end
end


utils.extract.uint8  = function(buffer, pos) return utils.extract.uint(buffer, pos, 1) end
utils.extract.uint16 = function(buffer, pos) return utils.extract.uint(buffer, pos, 2) end
utils.extract.uint32 = function(buffer, pos) return utils.extract.uint(buffer, pos, 4) end
utils.extract.int8   = function(buffer, pos) return utils.extract.int(buffer, pos, 1) end
utils.extract.int16  = function(buffer, pos) return utils.extract.int(buffer, pos, 2) end
utils.extract.int32  = function(buffer, pos) return utils.extract.int(buffer, pos, 4) end

utils.extract.ipv4 = function(buffer, pos)
    return tostring(buffer(pos, 4):ipv4())
end

utils.extract.buint8  = function(netByteOrder, buffer, pos) return utils.extract.buint(netByteOrder, buffer, pos, 1) end
utils.extract.buint16 = function(netByteOrder, buffer, pos) return utils.extract.buint(netByteOrder, buffer, pos, 2) end
utils.extract.buint32 = function(netByteOrder, buffer, pos) return utils.extract.buint(netByteOrder, buffer, pos, 4) end

-- merge array
utils.array.merge = function(left, right)
    local ret = {}
    for k,v in pairs(right) do ret[k] = v end
    for k,v in pairs(left) do ret[k] = v end
    return ret
end


utils.debug.print = function(...)
    info(table.concat({ "Lua: ", ... }, " "))
end


return utils
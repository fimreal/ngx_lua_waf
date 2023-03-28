-- actions
-- 规则处理函数
local _M = {
    _VERSION = "0.0.1",
    BlockEvilIP = false,
    expireTime = 600
}

local wafutils = require "lib.utils"

function _M.BlockIP()
    if not _M.BlockEvilIP then
        return
    end

    local ip = wafutils.GetClientIP()
    if ip == "unknown" then
        return
    end

    wafutils.logWarn(ip .. " in block IPList now. Expire time: " .. _M.expireTime .. "s")
    local ok, err, _ = ngx.shared.waf_block:set(ip, true, _M.expireTime)
    if not ok then
        wafutils.logErr(err)
    end
end

function _M.EnableBlockIP(duraction)
    _M.BlockEvilIP = true
    _M.expireTime = duraction
end

return _M

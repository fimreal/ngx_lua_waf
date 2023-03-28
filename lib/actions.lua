-- actions
-- 规则处理函数
local _M = {
    _VERSION = "0.0.1"
}

local wafutils = require "lib.utils"

function _M.BlockIP(exp)
    local ip = wafutils.GetClientIP()
    if ip == "unknown" then
        return
    end

    wafutils.logWarn("block IP: " .. ip)
    local blockDict = ngx.shared.waf_block
    blockDict:set(ip,1,exp)
end


return _M
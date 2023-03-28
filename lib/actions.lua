-- actions
-- 规则处理函数
local _M = {
    _VERSION = "0.0.1"
}

local wafutils = require "lib.utils"

function _M.AddBlockIP(exp)
    local ip = wafutils.GetClientIP()
    if ip == "unknown" then
        return
    end

    wafutils.logWarn(ip .. "in block IPList now. Expire time: " .. exp .. "s")
    local ok, err, _ = ngx.shared.waf_block:set(ip,true,exp)
    if not ok then
        wafutils.logErr(err)
    end
end


return _M
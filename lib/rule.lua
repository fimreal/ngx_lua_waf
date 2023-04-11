local wafutils = require "lib.utils"
local reMatch = ngx.re.match
local ipmatcher = require "lib.ipmatcher"

-- local ReqContentLength = tonumber(ngx.req.httpcontent_length)
-- local ReqMethod = ngx.req.get_method()

local _M = {
    _VERSION = "0.0.1"
}

------ 过滤函数 ------

-- 检查是否为内部子请求
function _M.IsInternal()
    return ngx.req.is_internal()
end

-- ip 过滤部分参考： https://github.com/whsir/ngx_lua_waf
-- XXX: 后续希望支持 cidr 判断

-- 判断是否为白 ip
function _M.IsWhiteIP(clientIP)
    -- local WafRule.IpWhiteList = wafutils.ReadFile(_M.WafRuleDir .. 'white_ip')
    if wafutils.IsNotEmpty(WafRule.IpWhiteList) then
        local whiteip, err = ipmatcher.new(WafRule.IpWhiteList)
        if err ~= nil and whiteip == nil then
            wafutils.logErr(err)
            return false
        end

        local ok, err = whiteip:match(clientIP)
        if err ~= nil then
            wafutils.logErr(err)
        end
        if ok then
            wafutils.logWarn(clientIP .. " is white ip")
        end
        return ok
        -- local clientIPDec = tonumber(wafutils.IP2Dec(clientIP))

        -- for _, whiteIP in pairs(WafRule.IpWhiteList) do
        --     local s, e = string.find(whiteIP, '-', 0, true)
        --     -- 匹配单 ip 
        --     if s == nil and clientIP == whiteIP then
        --         wafutils.logWarn(clientIP .. " is white ip, catch rule: " .. whiteIP)
        --         return true
        --     elseif s ~= nil then
        --         -- FIXME: 缺少 ip 可靠性判断
        --         local ipFrom = tonumber(wafutils.IP2Dec(string.sub(whiteIP, 0, s - 1)))
        --         local ipTo = tonumber(wafutils.IP2Dec(string.sub(whiteIP, e + 1)))
        --         if clientIPDec < ipFrom or clientIPDec > ipTo then
        --             return false
        --         end
        --         wafutils.logWarn(clientIP .. " is white ip, catch rule: " .. whiteIP)
        --         return true
        --     end
        -- end
    end
    return false
end

-- 判断是否为黑 ip
function _M.IsBlackIP(clientIP)
    -- local WafRule.IpBlackList = wafutils.ReadFile(_M.WafRuleDir .. 'black_ip')
    if wafutils.IsNotEmpty(WafRule.IpBlackList) then
        local blackip, err = ipmatcher.new(WafRule.IpWhiteList)
        if err ~= nil and blackip == nil then
            wafutils.logErr(err)
            return false
        end

        local ok, err = blackip:match(clientIP)
        if err ~= nil then
            wafutils.logErr(err)
        end
        if ok then
            wafutils.logWarn(clientIP .. " is black ip")
        end
        return ok
        -- local clientIPDec = tonumber(wafutils.IP2Dec(clientIP))

        -- for _, blackIP in pairs(WafRule.IpBlackList) do
        --     local s, e = string.find(blackIP, '-', 0, true)
        --     -- 匹配单 ip 
        --     if s == nil and clientIP == blackIP then
        --         wafutils.logWarn(clientIP .. " is black ip, catch rule: " .. blackIP)
        --         return true
        --     elseif s ~= nil then
        --         -- FIXME: 缺少 ip 可靠性判断
        --         local ipFrom = tonumber(wafutils.IP2Dec(string.sub(blackIP, 0, s - 1)))
        --         local ipTo = tonumber(wafutils.IP2Dec(string.sub(blackIP, e + 1)))
        --         if clientIPDec < ipFrom or clientIPDec > ipTo then
        --             return false
        --         end
        --         wafutils.logWarn(clientIP .. " is black ip, catch rule: " .. blackIP)
        --         return true
        --     end
        -- end
    end
    return false
end

function _M.IsBlockIp(clientIP)
    local exist = ngx.shared.waf_block:get(clientIP)
    if exist then
        return true
    end
    return false
end

-- 以下通过正则判断

-- function IsBlackHeader()
-- return false
-- end

-- request_uri 判断
function _M.IsWhiteUrl(uri)
    -- local WafRule.UrlWhiteRules = wafutils.ReadFile(_M.WafRuleDir .. 'white_url')
    if wafutils.IsNotEmpty(WafRule.UrlWhiteRules) then
        for _, rule in pairs(WafRule.UrlWhiteRules) do
            if reMatch(uri, rule, "isjo") then
                wafutils.logWarn(uri .. " is white uri, catch rule: " .. rule)
                return true
            end
        end
    end
    return false
end
function _M.IsBlackUrl(uri)
    -- local WafRule.UrlBlackRules = wafutils.ReadFile(_M.WafRuleDir .. 'white_url')
    if wafutils.IsNotEmpty(WafRule.UrlBlackRules) then
        for _, rule in pairs(WafRule.UrlBlackRules) do
            if reMatch(uri, rule, "isjo") then
                wafutils.logWarn(uri .. " is black uri, catch rule: " .. rule)
                return true
            end
        end
    end
    return false
end

-- query string 判断
-- 匹配 rule 文件中正则的返回 true
function _M.QueryStringFilter(args)
    if wafutils.IsNotEmpty(WafRule.QueryStringRule) then
        for _, rule in pairs(WafRule.QueryStringRule) do
            for key, val in pairs(args) do
                local data
                -- 判断是否为 table， args 中传入重复的 key ，value 存储为 table
                if type(val) == "table" then
                    -- "/test?foo&bar" val 为 true
                    -- "/test?foo=&bar=" val 为 false
                    -- 当传参没有赋值, 也就是 boolean 参数时，使用 key 来校验规则
                    if type(val) ~= "boolean" then
                        data = table.concat(val, ", ")
                    else
                        data = key
                    end
                else
                    data = val
                end

                if reMatch(ngx.unescape_uri(data), rule, 'isjo') then
                    wafutils.logWarn("find " .. data .. " in rule: " .. rule)
                    return true
                end
            end
        end
    end
    return false
end

-- req.host 判断
function _M.IsWhiteHost(host)
    -- local WafRule.HostWhiteRules = wafutils.ReadFile(_M.WafRuleDir .. 'white_host')
    if wafutils.IsNotEmpty(WafRule.HostWhiteRules) then
        for _, rule in pairs(WafRule.HostWhiteRules) do
            if reMatch(host, rule, "isjo") then
                wafutils.logWarn(host .. " is white host, catch rule: " .. rule)
                return true
            end
        end
    end
    return false
end
function _M.IsBlackHost(host)
    -- local WafRule.HostBlackRules = wafutils.ReadFile(_M.WafRuleDir .. 'black_host')
    if wafutils.IsNotEmpty(WafRule.HostBlackRules) then
        for _, rule in pairs(WafRule.HostBlackRules) do
            if reMatch(host, rule, "isjo") then
                wafutils.logWarn(host .. " is black host, catch rule: " .. rule)
                return true
            end
        end
    end
    return false
end

-- ua 判断
function _M.IsWhiteUA(ua)
    -- local WafRule.UaWhiteRules = wafutils.ReadFile(_M.WafRuleDir .. 'white_ua')
    if wafutils.IsNotEmpty(WafRule.UaWhiteRules) then
        for _, rule in pairs(WafRule.UaWhiteRules) do
            if reMatch(ua, rule, "isjo") then
                wafutils.logWarn(ua .. " is white ua, catch rule: " .. rule)
                return true
            end
        end
    end
    return false
end
function _M.IsBlackUA(ua)
    -- local WafRule.UaBlackRules = wafutils.ReadFile(_M.WafRuleDir .. 'black_ua')
    if wafutils.IsNotEmpty(WafRule.UaBlackRules) then
        for _, rule in pairs(WafRule.UaBlackRules) do
            if reMatch(ua, rule, "isjo") then
                wafutils.logWarn(ua .. " is black ua, catch rule: " .. rule)
                return true
            end
        end
    end
    return false
end

-- referer 判断
function _M.IsWhiteReferer(ref)
    -- local WafRule.RefWhiteRules = wafutils.ReadFile(_M.WafRuleDir .. 'white_referer')
    if wafutils.IsNotEmpty(WafRule.RefWhiteRules) then
        for _, rule in pairs(WafRule.RefWhiteRules) do
            if reMatch(ref, rule, "isjo") then
                wafutils.logWarn(ref .. " is white referer, catch rule: " .. rule)
                return true
            end
        end
    end
    return false
end
function _M.IsBlackReferer(ref)
    -- local WafRule.RefBlackRules = wafutils.ReadFile(_M.WafRuleDir .. 'black_referer')
    if wafutils.IsNotEmpty(WafRule.RefBlackRules) then
        for _, rule in pairs(WafRule.RefBlackRules) do
            if reMatch(ref, rule, "isjo") then
                wafutils.logWarn(ref .. " is black referer, catch rule: " .. rule)
                return true
            end
        end
    end
    return false
end

-- cookie 判断
function _M.IsWhiteCookie(cookie)
    if wafutils.IsNotEmpty(WafRule.CookieWhiteRule) then
        for _, rule in pairs(WafRule.CookieWhiteRule) do
            if reMatch(ref, rule, "isjo") then
                wafutils.logWarn(ref .. " is white cookie, catch rule: " .. rule)
                return true
            end
        end
    end
    return false
end
function _M.IsBlackCookie(cookie)
    if wafutils.IsNotEmpty(WafRule.CookieBlackRule) then
        for _, rule in pairs(WafRule.CookieBlackRule) do
            if reMatch(cookie, rule, "isjo") then
                wafutils.logWarn(cookie .. " is black cookie, catch rule: " .. rule)
                return true
            end
        end
    end
    return false
end

--
--
--
--
return _M

local init = require "lib.init"
local rule = require "lib.rule"
local wafutils = require "lib.utils"

local _M = {
    _VERSION = "0.1.0"
}

-- 初始化加载规则到全局变量
-- function _M.Init(ruleDir)
--     init.SetWafRuleDir(ruleDir)
--     init.LoadRule()
-- end
_M.Init = init.LoadRuleFromDir

-- 默认开启所有过滤，可以根据需要单独添加
function _M.ON()
    -- 忽略内部请求, 减少一次 waf 过滤损耗 
    -- 原因：如果配置在 access_by_lua 时可能会出现二次内部访问, 建议最好配置在 location 中
    -- ref. https://groups.google.com/g/openresty/c/9wjjtZMBGEk
    if rule.IsInternal() then
        wafutils.logDebug("skip internal req")
        return
    end

    -- 规则过滤
    _M.IpFilter()
    _M.HostFilter()
    _M.UrlFilter()
    _M.UserAgentFilter()
    _M.RefererFilter()

    -- 速率限制
    -- _M.LimitRate()
    -- _M.LimitConn()

    -- 待补充
    _M.ArgsFilter()

    -- 感觉用不到没添加
    -- _M.MethodFilter()
    -- _M.HeadersFilter()
end

-- 速率限制, 单个连接下载速度, 单位 b/s
function _M.LimitRate(rate)
    ngx.var.limit_rate = rate or nil
    return
end

-- 速率限制, 单个连接下载速度, 单位 c/s
-- 原版实现总感觉有问题, 暂时不启用, 后续尝试使用 https://github.com/openresty/lua-resty-limit-traffic
function _M.LimitConn()
    return
end

-- ip
-- 白名单优先级高于黑名单, 默认放行
function _M.IpFilter()
    wafutils.logDebug("start ip filter")
    -- 客户端 ip
    local clientIP = wafutils.GetClientIP()
    -- 未获取到 client ip 时, 默认警告并放行(通常 http/x 访问不会出现)
    if clientIP == "unknown" then
        wafutils.logAlert("not found clientIP")
        return
    end

    if rule.IsWhiteIP(clientIP) then
        return
    elseif rule.IsBlackIP(clientIP) then
        wafutils.logAlert(clientIP .. " is black ip")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    return

end

-- method 未实现
function _M.MethodFilter()
    return
end

-- host
-- 白名单优先级高于黑名单, 默认放行
-- 注意：容易误伤部分请求不传 host 的服务, 推荐使用黑名单控制
function _M.HostFilter()
    wafutils.logDebug("start host filter")
    local host = ngx.var.host or ""
    if host == "" then
        wafutils.logAlert("not found host")
        return
    end

    if rule.IsWhiteHost(host) then
        return
    elseif rule.IsBlackHost(host) then
        wafutils.logAlert(host .. " is black host")
        ngx.exit(ngx.HTTP_NOT_FOUND)
    end
    return
end

-- url
-- 白名单优先级高于黑名单，默认放行
-- 注意：index 或者 trans_files 等不和 uri 绑定的地址识别不到
function _M.UrlFilter()
    wafutils.logDebug("start url filter")
    -- $request_uri	请求的URI，带参数
    -- $uri	请求的URI，可能和最初的值有不同，比如经过重定向之类的
    local uri = ngx.var.request_uri or ""
    if uri == "" then
        wafutils.logAlert("not found uri")
        return
    end

    if rule.IsWhiteUrl(uri) then
        return
    elseif rule.IsBlackUrl(uri) then
        wafutils.logAlert(uri .. " is black uri")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    return
end

-- querystring / formdata
function _M.ArgsFilter()
    wafutils.logDebug("start args filter")
    local args = ngx.req.get_uri_args()
    if rule.QueryStringFilter(args) then
        wafutils.logAlert("request to " .. ngx.var.request_uri .. " in args filter rule")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    return
end

-- Headers 未实现
function _M.HeadersFilter()
    return
end

-- referer
function _M.RefererFilter()
    wafutils.logDebug("start referer filter")
    local ref = ngx.var.http_referer or ""
    if ref == "" then
        return
    end

    if rule.IsWhiteReferer(ref) then
        return
    elseif rule.IsBlackReferer(ref) then
        wafutils.logAlert(ref .. " is black referer")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    return
end

-- useragent
function _M.UserAgentFilter()
    wafutils.logDebug("start useragent filter")
    local ua = ngx.var.http_user_agent or ""
    if ua == "" then
        wafutils.logAlert("not found ua")
        return
    end

    if rule.IsWhiteUA(ua) then
        return
    elseif rule.IsBlackUA(ua) then
        wafutils.logAlert(ua .. " is black ua")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    return
end

return _M

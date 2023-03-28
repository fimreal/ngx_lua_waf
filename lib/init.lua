local wafutils = require("lib.utils")

local _M = {
    _VERSION = "0.0.1",
    WafRuleDir = "/etc/nginx/waf/rule/"
}

-- 修改规则目录
function _M.SetWafRuleDir(rulePath)
    -- 容忍目录少 /
    _M.WafRuleDir = rulePath .. "/"
end

-- 预加载到 table 中，减少环境污染
function _M.LoadRule()
    WafRule = {}
    WafRule.RuleDir = _M.WafRuleDir
    WafRule.IpWhiteList = wafutils.ReadFile(_M.WafRuleDir .. 'white_ip')
    WafRule.IpBlackList = wafutils.ReadFile(_M.WafRuleDir .. 'black_ip')
    WafRule.UrlWhiteRules = wafutils.ReadFile(_M.WafRuleDir .. 'white_url')
    WafRule.UrlBlackRules = wafutils.ReadFile(_M.WafRuleDir .. 'black_url')
    WafRule.HostWhiteRules = wafutils.ReadFile(_M.WafRuleDir .. 'white_host')
    WafRule.HostBlackRules = wafutils.ReadFile(_M.WafRuleDir .. 'black_host')
    WafRule.UaWhiteRules = wafutils.ReadFile(_M.WafRuleDir .. 'white_ua')
    WafRule.UaBlackRules = wafutils.ReadFile(_M.WafRuleDir .. 'black_ua')
    WafRule.RefWhiteRules = wafutils.ReadFile(_M.WafRuleDir .. 'white_referer')
    WafRule.RefBlackRules = wafutils.ReadFile(_M.WafRuleDir .. 'black_referer')
    WafRule.QueryStringRule = wafutils.ReadFile(_M.WafRuleDir .. 'querystring')
    WafRule.CookieWhiteRule = wafutils.ReadFile(_M.WafRuleDir .. 'white_cookie')
    WafRule.CookieBlackRule = wafutils.ReadFile(_M.WafRuleDir .. 'black_cookie')
end

function _M.LoadDynamicRule()
    return
end

function _M.LoadRuleFromDir(rulePath)
    _M.SetWafRuleDir(rulePath)
    _M.LoadRule()
    -- _M.LoadDynamicRule()
end

return _M

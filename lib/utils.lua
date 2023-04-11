-- utils
local _M = {}

-- 检查 table 是否为空，按照 openresty 最佳实践，最好不用 next 判断
function _M.IsNotEmpty(t)
    return t ~= nil or next(t) ~= nil
end

-- 读文件，每行存入 table 返回
-- 忽略 -- 及 # 开头行
function _M.ReadFile(filename)
    local f = io.open(filename, "r")
    local t = {}
    if f == nil then
        return t
    end
    _M.logNotice("waf load rule file -- " .. filename)
    for line in f:lines() do
        if not ngx.re.match(line, '^(--|#|$)') then
            table.insert(t, line)
        end
    end
    f:close()
    return t
end

-- 写文件, 由于 lua 模块不会自己创建文件，使用 shell 命令解决
function _M.write(filename, msg)
    os.execute("touch " .. filename)
    local fd = io.open(filename, "a+b")
    if fd == nil then
        _M.logErr("Can not write into file[" .. filename .. "]")
        return
    end
    fd:write(msg)
    fd:flush()
    fd:close()
end

-- 获取客户端 IP
function _M.GetClientIP()
    return ngx.var.http_x_real_ip or ngx.var.http_x_forwarded_for or ngx.var.remote_addr or "unknown"
end

-- format ip to decimal
function _M.IP2Dec(ip)
    local n = 4
    local decimalNum = 0
    local pos = 0
    for s, e in function()
        return string.find(ip, '.', pos, true)
    end do
        n = n - 1
        decimalNum = decimalNum + string.sub(ip, pos, s - 1) * (256 ^ n)
        pos = e + 1
        if n == 1 then
            decimalNum = decimalNum + string.sub(ip, pos, string.len(ip))
        end
    end
    return decimalNum
end

-- https://github.com/infiniroot/nginx-mitigate-log4shell/blob/main/mitigate-log4shell.conf
-- function _M.Decipher(v)
--     local s = tostring(v)
--     s = ngx.unescape_uri(s)
--     if string.find(s, "${base64:") then
--         t = (string.gsub(s, "${${base64:([%d%a%=]+)}}", "%1"))
--         s = string.gsub(s, "${base64:([%d%a%=]+)}", tostring(ngx.decode_base64(t)))
--     end
--     s = string.gsub(s, "${lower:(%a+)}", "%1")
--     s = string.gsub(s, "${upper:(%a+)}", "%1")
--     s = string.gsub(s, "${env:[%a_-]+:%-([%a:])}", "%1")
--     s = string.gsub(s, "${::%-(%a+)}", "%1")
--     if string.lower(s) == string.lower(tostring(v)) then
--         return string.lower(s)
--     else
--         return decipher(s)
--     end
-- end

function _M.logDebug(msg)
    ngx.log(ngx.DEBUG, msg)
end

function _M.logNotice(msg)
    ngx.log(ngx.NOTICE, msg)
end

function _M.logWarn(msg)
    ngx.log(ngx.WARN, msg)
end

function _M.logAlert(msg)
    ngx.log(ngx.ALERT, msg)
end

function _M.logErr(msg)
    ngx.log(ngx.ERR, msg)
end

return _M

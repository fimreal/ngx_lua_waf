# ngx_lua_waf

由于原项目作者很久不更新，fork 大佬项目，重写测试 ing (越改越不像原来项目了)

优势：

- lua 模块化，修改起来更容易
- 侵入性小，函数和变量尽量不存放于全局运行环境中
- 可以针对 location 单独配置不同过滤方式
- 配置文本化，方便 k8s 集群中作为 configmap 存储
- 包含 lua 模块的 nginx，或者直接使用 openresty 加载（支持版本未考究）


## 1. Quick start

克隆项目

```bash
cd /etc/nginx
git clone https://github.com/fimreal/ngx_lua_waf waf
```

添加 waf 配置

```nginx
http {
    ...

    lua_package_path '/etc/nginx/waf/?.lua;;';
    include /etc/nginx/waf/waf.conf;

    ...
}
```

自定义规则文件，支持 `--` 或者 `#` 开头的注释，每一行一次匹配，可使用 PCRE 正则

```bash
ls -l /etc/nginx/waf/rule
```

## 2. 具体食用方法

#### 2.1 配置 lua 加载目录，初始化加载 waf 配置

在 http 部分添加 lua 目录，例如将该项目克隆放在 `/etc/nginx/waf`,则添加配置

```nginx
# context: http
# 如果位置不在这里，注意修改
lua_package_path '/etc/nginx/waf/?.lua;;';

# load rule
init_by_lua_block {
    local waf = require "waf"
    -- 如果规则文件不在这里，注意修改
    waf.Init("/etc/nginx/waf/rule")
}
```

#### 2.2 在 vhost 中启用 waf

例子: 在 server 中默认开启 waf 所有过滤规则

```nginx
http {
    # context: http, server, location, location if
    # enable all filter
    access_by_lua_block {
        local waf = require "waf"
        waf.ON()
    }
}
```

配置可以放在 `http`, `server`, `location`, `location if` 中

支持过滤 ip、host、url、args、ua 等

例子： 只对某个 `location` 请求过滤

```nginx
server {
    ...

    location /path {
        ...
        # enable ip filter
        access_by_lua_block {
            local waf = require "waf"
            waf.IpFilter()
        }
    }
}
```

#### 2.3 封锁恶意 ip

例子: 在 server 中默认开启 waf 所有过滤规则, 同时对匹配到的 ip 封锁 600s

```nginx
http {
    # context: http, server, location, location if
    # enable all filter
    access_by_lua_block {
        local waf = require "waf"
        waf.EnableBlockIP(600)
        waf.ON()
    }
}
```

如果需要永久封禁，可以将时间改为 0，封禁 ip 记录重启后会丢失。持久化配置请加在 `rule/black_ip`

## z. 主要改动

z.1 移除原来旧的安装脚本。

    在如今成熟的 openresty 中加入 lua 很容易，只需要在配置文件中引用项目中 lua 文件即可。

引入包变为 module，减少环境污染。

z.2 参考宝塔修改的过滤规则更新

    宝塔用户量有保障，规则应该普适于绝大部分场景，企业用户自定义规则更好

    考虑到部分规则可能误伤，只选取了部分加入默认配置

z.3 增强 ip 过滤功能

    ip 过滤是最常见的 waf 功能，也是效率最高的过滤办法。

    相比于原版，增加了 cidr 规则配置，同时支持对恶意请求 ip 进行封锁。

z.4 新功能支持

    待补充

## LICENSE

MIT
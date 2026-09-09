# network_authentication

drcom 分支使用 Python 标准库实现 Dr.COM/ePortal 校园网认证，适合没有图形浏览器的 OpenWrt 环境。

已有 SRun 实现在 srun 分支；当前分支 drcom 只保留 Dr.COM/ePortal 逻辑，避免两套协议混在同一份代码里。

## 已识别的认证接口

~~~text
门户入口：http://<认证服务器>/
状态接口：http://<认证服务器>/drcom/chkstatus
登录接口：http://<认证服务器>:801/eportal/?c=Portal&a=login
注销接口：http://<认证服务器>:801/eportal/?c=Portal&a=logout
~~~

网页登录时提交的账号会被处理为 PC 端格式：,0,学号。脚本默认模拟这个行为。

## 使用

默认情况下，脚本会先访问一个普通 HTTP 探测 URL，利用校园网 captive portal 跳转自动提取认证服务器、wlanuserip、wlanacname 等上下文；如果没有捕获到跳转，再按到认证服务器的出接口自动识别本机 IPv4。入口 URL 里的 url 参数只是网页登录后的跳转目标，当前登录接口不需要单独发送。

直接运行：

~~~sh
python -m network_authentication status --host portal.example.edu
python -m network_authentication login --host portal.example.edu -u 学号 -p '密码'
python -m network_authentication logout --host portal.example.edu
~~~

如果自动探测失败，或者你确认需要固定某个 AC 名称，可以手动覆盖：

~~~sh
python -m network_authentication login \
  --host portal.example.edu \
  --ip '客户端IPv4' \
  --ac-name '接入控制器名称' \
  -u 学号 \
  -p '密码'
~~~

如果你拿到了浏览器或系统 captive portal 跳转出的完整入口 URL，仍然可以传 --portal-url 作为兼容兜底。脚本会从 URL 解析认证服务器、终端 IP、AC 名称等上下文：

~~~sh
python -m network_authentication login \
  --portal-url 'http://portal.example.edu/a79.htm?wlanuserip=client-ip&wlanacname=ac-name&url=http%3A%2F%2Fconnectivity.example%2Fgenerate_204' \
  -u 学号 \
  -p '密码'
~~~

注意：URL 里通常包含 &，在 shell 中必须用单引号或双引号包住整段 URL。

使用环境变量，避免把密码写进命令历史：

~~~sh
export DRCOM_USERNAME='学号'
export DRCOM_PASSWORD='密码'
export DRCOM_HOST='portal.example.edu'
python -m network_authentication login
~~~

也可以直接保存原始入口 URL 作为兼容兜底：

~~~sh
export DRCOM_PORTAL_URL='http://portal.example.edu/a79.htm?wlanuserip=client-ip&wlanacname=ac-name&url=http%3A%2F%2Fconnectivity.example%2Fgenerate_204'
export DRCOM_USERNAME='学号'
export DRCOM_PASSWORD='密码'
python -m network_authentication login
~~~

默认探测 URL 可以通过 DRCOM_PROBE_URL 或 --probe-url 调整；它只需要是会被未认证校园网拦截的普通 HTTP 地址即可。若想完全跳过自动探测，可以设置 DRCOM_NO_PROBE=1 或传 --no-probe。

如果账号需要运营商后缀：

~~~sh
python -m network_authentication login --host portal.example.edu -u 学号 -p '密码' --suffix @xyw
python -m network_authentication login --host portal.example.edu -u 学号 -p '密码' --suffix @dx
python -m network_authentication login --host portal.example.edu -u 学号 -p '密码' --suffix @lt
~~~

如果要完全自行控制发送给 Portal 的账号字段：

~~~sh
python -m network_authentication login --host portal.example.edu --raw-account -u ',0,学号' -p '密码'
~~~

## OpenWrt

~~~sh
opkg update
opkg install python3
~~~

复制仓库或源码后执行：

~~~sh
DRCOM_HOST='portal.example.edu' DRCOM_USERNAME='学号' DRCOM_PASSWORD='密码' python3 -m network_authentication login
~~~

需要开机自动认证时，可以把命令放到 /etc/rc.local 的 exit 0 之前。注意：环境变量或脚本里的密码是明文，请限制路由器管理权限。

## 常用参数

- --host：认证服务器地址；也可通过 DRCOM_HOST 配置
- --probe-url：触发 captive portal 跳转的 HTTP 探测 URL
- --no-probe：禁用 captive portal 自动探测
- --portal-url：原始认证入口 URL；自动探测失败时的兼容兜底
- --ip：手动覆盖自动探测到的终端 IPv4
- --ac-name：手动覆盖自动探测到的接入控制器名称
- --ac-ip：手动指定接入控制器 IP
- --mac：手动指定终端 MAC
- --vlan：手动指定 VLAN ID
- --json：输出完整响应，便于排障
- --force：即使状态接口显示已在线，也重新发送登录请求

## 开发验证

~~~sh
python -m unittest discover -s tests
~~~

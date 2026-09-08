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

直接运行：

~~~sh
python -m network_authentication status --host portal.example.edu
python -m network_authentication login --host portal.example.edu -u 学号 -p '密码'
python -m network_authentication logout --host portal.example.edu
~~~

使用环境变量，避免把密码写进命令历史：

~~~sh
export DRCOM_USERNAME='学号'
export DRCOM_PASSWORD='密码'
export DRCOM_HOST='portal.example.edu'
python -m network_authentication login
~~~

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
- --ip：手动指定终端 IPv4
- --mac：手动指定终端 MAC
- --vlan：手动指定 VLAN ID
- --json：输出完整响应，便于排障
- --force：即使状态接口显示已在线，也重新发送登录请求

## 开发验证

~~~sh
python -m unittest discover -s tests
~~~

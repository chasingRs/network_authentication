# network_authentication

一个基于 Python 的 SRun/Portal 校园网认证脚本

运行时只依赖 Python 标准库，直接执行 `python -m network_authentication` 即可，不需要额外安装第三方包。

## 安装

如果你希望以包的形式安装，也可以执行：

```bash
pip install -e .
```

## 使用

可以直接通过 CLI 传参：

```bash
python -m network_authentication ^
  --username your_id ^
  --password your_password ^
  --base-url http://your.portal.example.com
```

也可以使用环境变量，避免把账号密码写进源码：

```bash
set NETWORK_AUTH_USERNAME=your_id
set NETWORK_AUTH_PASSWORD=your_password
set NETWORK_AUTH_BASE_URL=http://your.portal.example.com
python -m network_authentication
```

出于隐私和可移植性考虑，仓库里不再内置任何真实门户地址；运行时请显式传入 `--base-url` 或设置 `NETWORK_AUTH_BASE_URL`：

```bash
python -m network_authentication ^
  --username your_id ^
  --password your_password ^
  --base-url http://your.portal.example.com ^
  --ac-id 1
```

常用参数：

- `--domain`：用户名后缀，例如 `@example.edu.cn`
- `--ip`：手动指定登录 IP；不传则使用 challenge 接口返回的 `online_ip`
- `--json`：打印完整响应 JSON
- `--otp`：使用 OTP 模式提交密码
- `--double-stack`：启用双栈参数

## 开发验证

```bash
python -m unittest discover -s tests
```

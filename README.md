# 📁 S.EE WebDAV

![Go](https://img.shields.io/badge/go-1.20%2B-00ADD8.svg)
![Release](https://img.shields.io/github/v/release/lhl77/see-webdav.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)

超级轻量的 [s.ee](https://s.ee) WebDAV 客户端，支持把上传文件代理到 s.ee 并通过 WebDAV 暴露为目录与文件。

## 快速开始

1. 下载对应系统的版本，推荐服务器部署

2. 编辑 `config.json`(首次运行生成)，填写端口和可选的 `see_token` 与 WebDAV 基本认证用户名/密码。

3. 添加权限并运行，推荐添加进程守护或作为系统服务运行。
```bash
$ chmod +x see-webdav
$ ./smms-webdav
```

默认监听 `:13876`（可在 `config.json` 修改）。

## 编译示例
```bash
# 在仓库根目录，Linux x86_64
$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o smms-webdav .
```

## 配置（`config.json`）

示例：

```json
{
  "see_token": "<YOUR_API_TOKEN>",
  "port": "13876",
  "username": "<WEBDAV_USERNAME>",
  "password": "WEBDAV_PASSWD"
}
```

## 配置 (反向代理和进程守护)
略，但是挺必要的。

## WebDAV 兼容

- 支持方法：GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, MOVE, OPTIONS。
- 上传（PUT）时会把文件上传到 S.EE，然后在本地 SQLite（`smms.db`）记录 `original_path`（上传时文件名）, `path`（S.EE云端PATH）, `hash`（删除图片所用Hash）, `url`（反代所用URL）, `size`, `modified`, `is_dir`。

## 适配图床
由于 WebDAV 协议没有回调，本项目内置了接口，但是需要手动调用，每个图床都不一样，详见： [LHL's Blog](https://blog.lhl.one/artical/542.html)

**Q:不配置回调可以吗？**
A:可以的，本项目支持GET方法访问图片，直接访问WEBDAV/<FILE_PATH>即可，会反代S.EE的图片，如果您的服务器线路不加可能会很慢。

## 许可证

MIT

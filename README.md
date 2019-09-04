# lua-nginx-autossl
基于openresty和consul  的自动识别https证书

## 概述
lua-nginx-autossl 是为了解决多域名、多节点机器配置ssl证书而生。
常见场景就是相同的nginx配置，由于不同的域名，需要维护多份配置。并且通常nginx也是多个节点服务的，所以更新证书或分发证书也不是很方便。因此，本项目是使用了consul的kv功能存储`Let's Encrypt`或者其它渠道申请下来的PEM证书，`openresty`定时轮询将证书和私钥存到全局共享字典`lua_shared_dict`，再在nginx 的 `ssl_certificate_by_lua_block` 阶段，根据请求的`server_name` 从全局字典取对应的证书。理论上全局字典只是全内存操作，不会带来性能问题。
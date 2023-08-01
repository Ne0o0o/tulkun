# Tulkun

![go-version](https://img.shields.io/github/go-mod/go-version/Ne0o0o/tulkun)
![license](https://img.shields.io/github/license/Ne0o0o/tulkun)
> Tulkun（图鲲）是基于 eBPF 技术实现的轻量主机入侵检测工具

## 核心功能设计

- 「事件驱动」拥有较高的性能表现
- 「网络监控」DNS 及 HTTPS 等网络流量捕获
- 「进程监控」进程信息监控
- 「文件监控」核心文件监控
- 「入侵检测」RASP 检测
- 「容器扩展」扩展关联容器信息

## 运行方式

推荐使用 ubuntu:22.04 编译运行

### 安装编译环境

```shell
sh install/install-compile-env.sh
```

### 编译运行

```shell
make tulkun-ebpf && sudo ./tulkun-ebpf
```

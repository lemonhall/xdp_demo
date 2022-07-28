
### 参考资料

https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/
https://developers.redhat.com/blog/2021/04/01/get-started-with-xdp

### 先拿到一个bash

* bash

### 更新源并且更新ca

* apt update
* apt upgrade
* apt install ca-certificates

### 安装vim

* apt install vim

否则不方便搞事情


### 修改源

https://mirror.tuna.tsinghua.edu.cn/help/ubuntu/


	# 默认注释了源码镜像以提高 apt update 速度，如有需要可自行取消注释
	deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy main restricted universe multiverse
	# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy main restricted universe multiverse
	deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-updates main restricted universe multiverse
	# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-updates main restricted universe multiverse
	deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-backports main restricted universe multiverse
	# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-backports main restricted universe multiverse
	deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-security main restricted universe multiverse
	# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-security main restricted universe multiverse

	# 预发布软件源，不建议启用
	# deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-proposed main restricted universe multiverse
	# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-proposed main restricted universe multiverse


### 镜像正常化一下

* unminimize

### 解决一下编码

* apt install locales

* dpkg-reconfigure locales

	# vim ~/.bashrc_profile
	# LANG="zh_CN.utf8"
	# export LANG

然后验证一下

* locale

### 安装包

apt install clang llvm gcc libbpf0 libbpf-dev
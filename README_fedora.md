### 安装依赖

dnf update

* 安装编译器部分
dnf install clang llvm gcc

* 安装bpf和xdp部分
dnf install libbpf libbpf-devel libxdp libxdp-devel xdp-tools bpftool

* 安装headers
dnf install kernel-headers

* 全部合起来是：
dnf install clang llvm gcc libbpf libbpf-devel libxdp libxdp-devel xdp-tools bpftool kernel-headers


### 第一个例子

	#include <linux/bpf.h>
	#include <bpf/bpf_helpers.h>

	SEC("xdp_drop")
	int xdp_drop_prog(struct xdp_md *ctx)
	{
	    return XDP_DROP;
	}

	char _license[] SEC("license") = "GPL";

编译之

	clang -O2 -g -Wall -target bpf -c xdp_drop.c -o xdp_drop.o

### 安装 ip
dnf install iproute

https://access.redhat.com/sites/default/files/attachments/rh_ip_command_cheatsheet_1214_jcs_print.pdf

	link set Alter the status of the interface
			ip link set em1 up
			Bring em1 online
			ip link set em1 down
			Bring em1 offline
			ip link set em1 mtu 9000
			Set the MTU on em1 to 9000
			ip link set em1 promisc on
			Enable promiscuous mode for em1

ip link set veth1 xdpgeneric obj xdp_drop.o sec xdp_drop

	[root@865546eb776c xdp]# ip link set veth1 xdpgeneric obj xdp_drop.o sec xdp_drop
	mount --make-private /sys/fs/bpf failed: Operation not permitted
	Continuing without mounted eBPF fs. Too old kernel?
	mkdir (null)/globals failed: No such file or directory
	[root@865546eb776c xdp]#

   16  dnf install bison
   17  make
   18  dnf install flex

 https://stackoverflow.com/questions/56730076/error-trying-to-run-xdp-on-my-device-driver

ip -force link set veth1 xdpgeneric obj xdp_drop.o sec xdp_drop
 
https://github.com/cilium/cilium/issues/10731
https://forum.snapcraft.io/t/cant-start-snaps-cannot-create-sys-fs-bpf-snap-directory/28468

https://docs.cilium.io/en/v1.7/install/system_requirements/#linux-kernel

CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_NET_CLS_BPF=y
CONFIG_BPF_JIT=y
CONFIG_NET_CLS_ACT=y
CONFIG_NET_SCH_INGRESS=y
CONFIG_CRYPTO_SHA1=y
CONFIG_CRYPTO_USER_API_HASH=y


https://superuser.com/questions/287371/obtain-kernel-config-from-currently-running-linux-system
看一下当前的参数

gzip -d filename.gz

我在这里找到了：/proc/config.gz
然后用gzip解压了

最后config文件就是当前的config

然后我发现CONFIG_BPF=y
是没问题的。。。。

ip link set veth1 xdpgeneric obj xdp_drop.o sec xdp_drop
ip link set dev em1 xdp obj xdp_drop.o sec xdp_drop

https://github.com/cilium/cilium/issues/3717

https://zhengyinyong.com/post/bpftool-cheatsheet/

如果此时没有 bpffs，可执行：

1
mount -t bpf none /sys/fs/bpf/


https://www.kitploit.com/2022/07/bpflock-ebpf-driven-security-for.html?m=1


https://linuxhint.com/check-version-update-fedora-linux-kernel/#:~:text=The%20best%20way%20to%20update,run%20the%20following%20DNF%20command.

我才发现一个奇怪的问题

https://codeantenna.com/a/yIKCotrUuf

docker镜像中centos内核升级到指定内核版本（由于docker镜像中的内核与宿主机的内核是一个东西或者说docker镜像里不包含内核， 因此只需要将宿主机的内核升到指定版本)

container 不会跑自己的 kernel ，用的还是宿主机的 kernel 。

所以 docker 里很多系统级的操作需要在启动时额外增加权限，默认是不允许的。因为这些操作将直接影响宿主机。

容器是和宿主共用了相同的内核，但有一个kata-containers的项目，用了一个非常轻量的定制化内核来跑容器，简单来说就相当于宿主上跑虚拟机，虚拟机里面在运行容器。这应该可以解决你的需求。


我这才明白了：
docker run -it alpine uname -a

https://stackoverflow.com/questions/64000123/can-i-change-the-linux-kernel-that-docker-uses-on-macos

也就是说在macOS下跑一个docker desktop，那么你的内核永远都是。。。。跟着host走的 


### 拉一个老版本
docker pull fedora:33

dnf --showduplicates list kernel-headers

https://koji.fedoraproject.org/koji/packageinfo?buildStart=750&packageID=8&buildOrder=-completion_time&tagOrder=name&tagStart=0#buildlist

BPF虚拟文件系统是干什么的，以及它的作用

https://blog.csdn.net/weixin_41036447/article/details/106589229



docker run -it --rm --privileged --env="DISPLAY=host.docker.internal:0" -v /tmp/.X11-unix:/tmp/.X11-unix lemonhall/ubuntu_desktop bash



https://andreybleme.com/2022-05-22/running-ebpf-programs-on-docker-containers/

Docker privileged mode grants a Docker container root capabilities to all devices on the host system. You should always spin up your BPF container by running:

$ docker run -it --privileged ebpf-playground:1.0.0


docker ps -a

docker commit -m "ubuntu desktop" -a "lemonhall" 6f57225a5494 lemonhall/ubuntu_desktop

26a4632c0568

docker run -it --rm --env="DISPLAY=host.docker.internal:0" -v /tmp/.X11-unix:/tmp/.X11-unix lemonhall/ubuntu_desktop Xsession

docker commit -m "eBPF" -a "lemonhall" 8bbefd9fc9f2 lemonhall/ebpf


### 成功运行

docker run -it --rm --privileged -v /sys/fs/bpf:/sys/fs/bpf lemonhall/ebpf bash

	[root@25a128e5c805 /]# mount -t bpf none /sys/fs/bpf/
	[root@25a128e5c805 /]# bpftool prog list
	3: cgroup_device  tag 531db05b114e9af3
		loaded_at 2022-07-28T00:13:46+0000  uid 0
		xlated 512B  jited 325B  memlock 4096B
	6: cgroup_device  tag 531db05b114e9af3
		loaded_at 2022-07-28T00:13:46+0000  uid 0
		xlated 512B  jited 325B  memlock 4096B
	9: cgroup_device  tag 531db05b114e9af3
		loaded_at 2022-07-28T00:13:46+0000  uid 0
		xlated 512B  jited 325B  memlock 4096B

这下竟然能看到宿主机器的eBPF的程序了

docker run -it --rm --privileged lemonhall/ebpf bash


### 看状态

[root@8cf0c9e8c452 ~]# xdp-loader status

CURRENT XDP PROGRAM STATUS:

	Interface        Prio  Program name      Mode     ID   Tag               Chain actions
	--------------------------------------------------------------------------------------
	lo                     <No XDP program loaded!>
	tunl0                  <No XDP program loaded!>
	ip6tnl0                <No XDP program loaded!>
	eth0                   <No XDP program loaded!>

	[root@8cf0c9e8c452 ~]#


### load程序
[root@8cf0c9e8c452 ~]# xdp-loader load -m skb -s xdp_drop ip6tnl0 xdp_drop.o

### unload一个程序
 xdp-loader unload ip6tnl0 -i 149
 
### 启动一个虚拟的界面
https://copyprogramming.com/howto/veth-interface-configuration-persistent


	[root@5e167b346a92 xdp]# ip link add veth0 type veth peer name veth1
	[root@5e167b346a92 xdp]# ip addr add 10.1.0.1/24 dev veth0
	ip addr add 10.1.0.2/24 dev veth1
	[root@5e167b346a92 xdp]# ip link set veth0 up
	ip link set veth1 up
	[root@5e167b346a92 xdp]# ip link
	1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
	    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
	2: tunl0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default qlen 1000
	    link/ipip 0.0.0.0 brd 0.0.0.0
	3: sit0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default qlen 1000
	    link/sit 0.0.0.0 brd 0.0.0.0
	4: veth1@veth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
	    link/ether ce:9f:65:54:7a:ba brd ff:ff:ff:ff:ff:ff
	5: veth0@veth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
	    link/ether 2e:6a:e3:7a:d2:23 brd ff:ff:ff:ff:ff:ff
	16: eth0@if17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default
	    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff link-netnsid 0
	[root@5e167b346a92 xdp]#

	# create veth pair and assing IP address.
	ip link add veth0 type veth peer name veth1
	ip addr add 10.1.0.1/24 dev veth0
	ip addr add 10.1.0.2/24 dev veth1
	# bring up the interfaces
	ip link set veth0 up
	ip link set veth1 up
	
* 简单来说就这四句话，这样，就可以安全的搞事情了

然后用ip来挂

ip link set veth1 xdpgeneric obj xdp_drop.o sec xdp_drop

完美，啥问题都没有

* xdp-loader status

![image](https://user-images.githubusercontent.com/637919/181520826-3c34e2a5-3c06-4589-9bac-c887aadd8a87.png)


看一下状态，成功load了，非常好

[Create Your Own Network Namespace](https://itnext.io/create-your-own-network-namespace-90aaebc745d)

参考一下这篇文章，理解一下veth的事情先，然后继续



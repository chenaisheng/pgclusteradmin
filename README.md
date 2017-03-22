# pgclusteradmin

Pgclusteradmin是一款基于go开发的postgresql集群管理工具，当前主要功能是实现对postgresql服务进行管理，主备切换进行管理；系统支持多用户，操作认证；操作人员通过浏览器从远程登录进入管理平台，前面的界面使用easyui实现。

###一、功能列表

* 节点资料增加，编辑，删除
* 单一节点服务start、stop、restart、reload及显示服务状态
* 主备节点一键切换

###二、部署环境

* Ip：192.168.1.10
* os：centos 7.0 
* golang: go version go1.7.4 linux/amd64
* Postgresql：9.6.1 

###三、Pgclusteradmin环境需求

####安装golang

* [root@ad ~]# yum install golang-1.7.4-1.el6.x86_64.rpm  
* [root@ad ~]# yum install golang-src-1.7.4-1.el6.noarch.rpm
* [root@ad ~]# yum install golang-bin-1.7.4-1.el6.x86_64.rpm


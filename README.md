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

####安装postgresql 

* 使用postgresql主要是用于存储管理节点资料，操作员资料及操作日志

－－下载源码

    wget https://ftp.postgresql.org/pub/source/v9.6.1/postgresql-9.6.1.tar.gz

－－解压

    tar zxf postgresql-9.6.1.tar.gz

－－编译

    cd postgresql-9.6.1
    ./configure --prefix=/usr/local/pgsql9.6.1 --with-perl --with-tcl --with-python --with-openssl --with-pam --without-ldap --with-libxml --with-libxslt
    gmake 
    gmake install

－－初始化

    su postgres
    /usr/local/pgsql9.6.1/bin/initdb -D /home/postgres/data9.6.1 -E utf8 -U postgres -W

－－postgresql.conf配置

    listen_addresses = '*'
    log_destination = 'stderr'
    logging_collector = on

－－pg_hba.conf配置

    host    all             all             192.168.1.0/24          md5

配置完成后需要重启服务,其它参数视需要自己配置

建立pgclusteradmin库并导入建立资料表

    /usr/local/pgsql9.6.1/bin/psql -h 192.168.1.10 -U postgres -d postgres -p 5432 
    postgres=# create database pgcluster ENCODING 'utf8' template template0;
    \c pgcluster

－－导入下面数据表及数据

--节点资料表

    create table nodes
    (
       id serial not null unique,
       node_name text not null unique,    
       createtime timestamp not null default now(),
       host text not null,          
       ssh_port integer not null,
       ssh_user text not null,
       ssh_password text not null,  
       pg_bin text not null,
       pg_data text not null,
       pg_port integer not null,
       pg_database text not null,
       pg_user text not null,
       pg_password text not null,
       master_vip text,
       master_vip_networkcard text,
       slave_vip text,
       slave_vip_networkcard text,
       bind_vip_user text,
       bind_vip_password text,   
       remark text 
    );

    COMMENT ON TABLE nodes IS '节点资料表';
    COMMENT ON COLUMN nodes.id IS '系统编号';
    COMMENT ON COLUMN nodes.node_name IS '节点名称';   
    COMMENT ON COLUMN nodes.createtime IS '建立时间';   
    COMMENT ON COLUMN nodes.host IS '主机名或ip';   
    COMMENT ON COLUMN nodes.ssh_port IS 'ssh服务端口号';   
    COMMENT ON COLUMN nodes.ssh_user IS 'ssh用户';   
    COMMENT ON COLUMN nodes.ssh_password IS 'ssh密码';  
    COMMENT ON COLUMN nodes.pg_bin IS 'pg管理程序所在路径';    
    COMMENT ON COLUMN nodes.pg_data IS 'pgDATA所在路径';      
    COMMENT ON COLUMN nodes.pg_port IS 'pg服务端口号';   
    COMMENT ON COLUMN nodes.pg_user IS 'pg用户';   
    COMMENT ON COLUMN nodes.pg_password IS 'pg密码';   
    COMMENT ON COLUMN nodes.master_vip IS '主节点时绑定VIP'; 
    COMMENT ON COLUMN nodes.master_vip_networkcard IS '主节点时绑定网卡设备号';                  
    COMMENT ON COLUMN nodes.slave_vip IS '备节点时绑定VIP';                  
    COMMENT ON COLUMN nodes.slave_vip_networkcard IS '备节点时绑定网卡设备号';                  
    COMMENT ON COLUMN nodes.bind_vip_user IS '绑定网卡操作用户';                  
    COMMENT ON COLUMN nodes.bind_vip_password IS '绑定网卡操作密码';         

--操作员资料表

    CREATE TABLE users
    (
        id serial not null unique,
        username text not null unique,
        password text not null
    );

    COMMENT ON TABLE users IS '操作员资料表';
    COMMENT ON COLUMN users.id IS '系统编号';
    COMMENT ON COLUMN users.username IS '登录账号';
    COMMENT ON COLUMN users.password IS '登录密码md5值';

--增加一个操作员记录表

    INSERT INTO users (username,password) values('admin',md5('admin'));

--操作日志表

    CREATE TABLE log
    (
        id serial not null unique,
        createtime timestamp not null default now(),
        remote_ip text,
        modlename text,
        username text,
        log_level text,
        remark text 
    );
    COMMENT ON TABLE log IS '日志表';
    COMMENT ON COLUMN log.id IS '系统编号';
    COMMENT ON COLUMN log.createtime IS '访问时间';
    COMMENT ON COLUMN log.remote_ip IS '访问客户端ip地址';
    COMMENT ON COLUMN log.username IS '用户名';  
    COMMENT ON COLUMN log.modlename IS '模块名称';
    COMMENT ON COLUMN log.log_level IS '日志级别';
    COMMENT ON COLUMN log.remark IS '日志内容';

####下载pgclusteradmin所需要的go支持包

－－ssh支持包

    [root@ad ~]# cd /usr/lib/golang/src
    [root@ad src]# mkdir golang.org
    [root@ad src]# cd golang.org/
    [root@ad golang.org]# mkdir x
    [root@ad src]# cd x/
    [root@ad x]# git clone https://github.com/golang/crypto.git
    正克隆到 'crypto'...
    remote: Counting objects: 3256, done.
    remote: Total 3256 (delta 0), reused 0 (delta 0), pack-reused 3255
    接收对象中: 100% (3256/3256), 2.31 MiB | 958.00 KiB/s, done.
    处理 delta 中: 100% (2106/2106), done.

－－session支持包

    [root@ad x]# cd /usr/lib/golang/src
    [root@ad src]# mkdir github.com
    [root@ad src]# cd github.com
    [root@ad github.com]# mkdir astaxie
    [root@ad github.com]# cd astaxie/
    [root@ad astaxie]# git clone https://github.com/astaxie/session
    正克隆到 'session'...
    remote: Counting objects: 50, done.
    remote: Total 50 (delta 0), reused 0 (delta 0), pack-reused 50
    Unpacking objects: 100% (50/50), done.
    [root@ad astaxie]# ll
    总用量 8

－－postgresql操作支持包

    [root@ad astaxie]# cd /usr/lib/golang/src/github.com/
    [root@ad github.com]# mkdir jackc
    [root@ad github.com]# cd jackc
    [root@ad jackc]# git clone https://github.com/jackc/pgx
    正克隆到 'pgx'...
    remote: Counting objects: 3613, done.
    remote: Compressing objects: 100% (243/243), done.
    remote: Total 3613 (delta 157), reused 0 (delta 0), pack-reused 3370
    接收对象中: 100% (3613/3613), 1.24 MiB | 228.00 KiB/s, done.
    处理 delta 中: 100% (2481/2481), done.
    
###四、pgclusteradmin部署配置和访问

####下载pgclusteradmin源码

    [root@ad pgclusteradmin]# cd /home/ad
    [root@ad ad]# git clone https://github.com/chenaisheng/pgclusteradmin
    正克隆到 'pgclusteradmin'...
    remote: Counting objects: 374, done.
    remote: Compressing objects: 100% (177/177), done.
    remote: Total 374 (delta 201), reused 348 (delta 185), pack-reused 0
    接收对象中: 100% (374/374), 284.09 KiB | 197.00 KiB/s, done.
    处理 delta 中: 100% (201/201), done.
    [root@ad ad]#

####运行pgclusteradmin

    [root@ad ad]# cd pgclusteradmin/
    [root@ad pgclusteradmin]# go run pgclusteradmin.g

####访问pgclusteradmin

    打开一个浏览器，输入 http://192.168.1.10:10001即可进入管理器，192.168.1.10换成你自己ip地址即可。

###五、界面图 

####主界面说明    
![](https://github.com/chenaisheng/pgclusteradmin/blob/master/gui_image/%E4%B8%BB%E7%95%8C%E9%9D%A2%E8%AF%B4%E6%98%8E.png)

####添加节点
![](https://github.com/chenaisheng/pgclusteradmin/blob/master/gui_image/%E6%B7%BB%E5%8A%A0%E8%8A%82%E7%82%B9.png)

####服务管理
![](https://github.com/chenaisheng/pgclusteradmin/blob/master/gui_image/%E6%9C%8D%E5%8A%A1%E7%AE%A1%E7%90%86.png)

####主备切换
![](https://github.com/chenaisheng/pgclusteradmin/blob/master/gui_image/%E4%B8%BB%E5%A4%87%E5%88%87%E6%8D%A2.png)
    
###六、更新日志
    
####2017-3-3号

* 1、修正 "promote_get_ip_bind_statusHandler" 接口（获取主备节点ip绑定情况接口），变成异步同时获取主备节点的ip绑定详情，提高程序的响应速度
* 2、修正 "insertnodeHandler" 接口（增加节点资料），提前执行rows.Close() 的错误
* 3、修改 "insertnodeHandler"和"updatenodeHandler" 接口（修改节点资料），限制host+pg_port不能重复
* 4、修正 index.html中前端删除节点资料后,在没刷新的情况下无法执行主备切换功能
* 5、修正 index.html中前端主备切换判断主备节点类型不正确的bug
* 6、修正 get_node_ip_bind_status接口中执行ip a命令ip找不到的错误

####2017-3-4号

* 1、修正 项目中所有找不到ip命令和ifconfig命令的错误

####2017-3-7号

* 1、修改"promoteHandler"接口,由原来的顺序执行修改为多次异步执行



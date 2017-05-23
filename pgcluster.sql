create table nodes
(
   id serial not null unique,
   node_name text not null unique,    
   createtime timestamp not null default now(),
   host text not null,          
   ssh_port integer not null,
   ssh_user text not null,
   ssh_password text not null,  
   ssh_authmethod text not null default 'key',
   pg_bin text not null,
   pg_data text not null,
   pg_log text not null default '',
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
   bind_vip_authmethod text default 'key', 
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
COMMENT ON COLUMN nodes.ssh_authmethod IS '用户登录ssh服务认证方式，其值只能是key或者password';  
COMMENT ON COLUMN nodes.pg_bin IS 'pg管理程序所在路径';    
COMMENT ON COLUMN nodes.pg_data IS 'pgDATA所在路径';      
COMMENT ON COLUMN nodes.pg_log IS '用户访问日志保存路径';      
COMMENT ON COLUMN nodes.pg_port IS 'pg服务端口号';   
COMMENT ON COLUMN nodes.pg_user IS 'pg用户';   
COMMENT ON COLUMN nodes.pg_password IS 'pg密码';   
COMMENT ON COLUMN nodes.master_vip IS '主节点时绑定VIP'; 
COMMENT ON COLUMN nodes.master_vip_networkcard IS '主节点时绑定网卡设备号';                  
COMMENT ON COLUMN nodes.slave_vip IS '备节点时绑定VIP';                  
COMMENT ON COLUMN nodes.slave_vip_networkcard IS '备节点时绑定网卡设备号';                  
COMMENT ON COLUMN nodes.bind_vip_user IS '绑定网卡操作用户';                  
COMMENT ON COLUMN nodes.bind_vip_password IS '绑定网卡操作密码';    
COMMENT ON COLUMN nodes.bind_vip_authmethod IS '绑定网卡操作用户登录ssh服务认证方式，其值只能是key或者password';     

CREATE INDEX nodes_node_name_idx ON nodes USING BTREE(node_name);
CREATE INDEX nodes_createtime_idx ON nodes USING BTREE(createtime);            

CREATE TABLE users
(
    id serial not null unique,
    username text not null unique,
    password text not null
);

COMMENT ON TABLE users IS '用户表';
COMMENT ON COLUMN users.id IS '系统编号';
COMMENT ON COLUMN users.username IS '登录账号';
COMMENT ON COLUMN users.password IS '登录密码md5值';

INSERT INTO users (username,password) values('admin',md5('admin'));

CREATE TABLE errhandle_log
(
    id serial not null unique,
    createtime timestamp not null default now(),
    remote_ip text,
    modlename text,
    username text,
    error_msg text 
);
COMMENT ON TABLE errhandle_log IS '错误日志表';
COMMENT ON COLUMN errhandle_log.id IS '系统编号';
COMMENT ON COLUMN errhandle_log.createtime IS '生成时间';
COMMENT ON COLUMN errhandle_log.remote_ip IS '访问客户端ip地址';
COMMENT ON COLUMN errhandle_log.username IS '用户名';  
COMMENT ON COLUMN errhandle_log.modlename IS '模块名称';
COMMENT ON COLUMN errhandle_log.error_msg IS '错误内容';

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


CREATE TABLE parameter_bak_template
(
    id serial not null unique,
	nodeid integer not null,
	createtime timestamp not null default now(),
	username text not null,
	filename text not null,
	version  text not null,
	content  text not null,
	category text not null,
	remark   text not null
);
COMMENT ON TABLE parameter_bak_template IS '参数文件备份或者模板表';
COMMENT ON COLUMN parameter_bak_template.id IS '系统编号';
COMMENT ON COLUMN parameter_bak_template.nodeid IS '节点id号';
COMMENT ON COLUMN parameter_bak_template.createtime IS '备份日期';
COMMENT ON COLUMN parameter_bak_template.username IS '操作员账号';
COMMENT ON COLUMN parameter_bak_template.filename IS '文件名称';
COMMENT ON COLUMN parameter_bak_template.version IS '版本号';
COMMENT ON COLUMN parameter_bak_template.content IS '内容';
COMMENT ON COLUMN parameter_bak_template.category IS '类别，值为bak或者template';
COMMENT ON COLUMN parameter_bak_template.remark IS '备注';


CREATE TABLE inspection_report
(
	id serial not null unique,
	nodeid integer not null,
	report_name   text not null,
	createtime timestamp not null default now(),
	count_finish text not null default '否',
	username text not null
);
COMMENT ON TABLE inspection_report IS '巡检报表';
COMMENT ON COLUMN inspection_report.id IS '系统编号';
COMMENT ON COLUMN inspection_report.nodeid IS '节点id号';
COMMENT ON COLUMN inspection_report.report_name IS '报表名称';
COMMENT ON COLUMN inspection_report.createtime IS '生成日期';
COMMENT ON COLUMN inspection_report.count_finish IS '统计已完成';
COMMENT ON COLUMN inspection_report.username IS '操作员账号';


CREATE INDEX inspection_report_nodeid_idx ON inspection_report USING btree(nodeid);


CREATE TABLE inspection_report_role
(
	id serial not null unique,
	inspection_report_id integer not null,
	rolname text not null,
	rolcomment text not null,
	rolsuper varchar(1) not null,
	rolcreaterole varchar(1) not null,
	rolcreatedb varchar(1) not null,
	rolcanlogin varchar(1) not null,
	rolreplication varchar(1) not null,
	rolconnlimit integer not null,
	rolpassword_state text not null,
	rolvaliduntil timestamptz,
	datnum bigint,
	tablenum bigint,
	indexnum bigint 
);

COMMENT ON TABLE inspection_report_role IS '巡检报表--角色统计';
COMMENT ON COLUMN inspection_report_role.id IS '系统编号';
COMMENT ON COLUMN inspection_report_role.inspection_report_id IS '巡检报表－系统编号';
COMMENT ON COLUMN inspection_report_role.rolname IS '用户名';
COMMENT ON COLUMN inspection_report_role.rolcomment IS '注释';
COMMENT ON COLUMN inspection_report_role.rolsuper IS '超级用户';
COMMENT ON COLUMN inspection_report_role.rolcreaterole IS '准许创建用户';
COMMENT ON COLUMN inspection_report_role.rolcreatedb IS '准许创建数据库';
COMMENT ON COLUMN inspection_report_role.rolcanlogin IS '准许登录';
COMMENT ON COLUMN inspection_report_role.rolreplication IS '复制角色';
COMMENT ON COLUMN inspection_report_role.rolconnlimit IS '并发连接数';
COMMENT ON COLUMN inspection_report_role.rolpassword_state IS '口令状态，分为‘加密’，‘未加密’，‘无密码’';
COMMENT ON COLUMN inspection_report_role.rolvaliduntil IS '口令过期时间';
COMMENT ON COLUMN inspection_report_role.datnum IS '数据库数';
COMMENT ON COLUMN inspection_report_role.tablenum IS '数据表数';
COMMENT ON COLUMN inspection_report_role.indexnum IS '索引数';

CREATE INDEX inspection_report_role_inspection_report_id_idx ON inspection_report_role USING BTREE(inspection_report_id);

CREATE TABLE inspection_report_tablespace
(
	id serial not null unique,
	inspection_report_id integer not null,
	spcname text not null,
	spccomment text not null,
	spcowner text not null,
	location text not null,
	spcsize bigint not null,
	tablenum bigint ,
	indexnum bigint
);

COMMENT ON TABLE inspection_report_tablespace IS '巡检报表--表空间统计';
COMMENT ON COLUMN inspection_report_tablespace.id IS '系统编号';
COMMENT ON COLUMN inspection_report_tablespace.inspection_report_id IS '巡检报表－系统编号';
COMMENT ON COLUMN inspection_report_tablespace.spcname IS '表空间名';
COMMENT ON COLUMN inspection_report_tablespace.spccomment IS '注释';
COMMENT ON COLUMN inspection_report_tablespace.spcowner IS '所有者';
COMMENT ON COLUMN inspection_report_tablespace.location IS '路径';
COMMENT ON COLUMN inspection_report_tablespace.spcsize IS '占用空间';
COMMENT ON COLUMN inspection_report_tablespace.tablenum IS '数据表数';
COMMENT ON COLUMN inspection_report_tablespace.indexnum IS '索引数';

CREATE INDEX inspection_report_tablespace_inspection_report_id_idx ON inspection_report_tablespace USING BTREE(inspection_report_id);

CREATE TABLE inspection_report_database
(
	id serial not null unique,
	inspection_report_id integer not null,
	datname text not null,
	datcomment text not null,
	datdba text not null,
	encoding text not null,
	datcollate text not null,
	datctype text not null,
	datistemplate varchar(1) not null,
	datallowconn varchar(1) not null,
	datconnlimit integer not null,
	dattablespace text not null,
	datsize bigint not null,
	tablenum bigint ,
	indexnum bigint 
);
COMMENT ON TABLE inspection_report_database IS '巡检报表--数据库统计';
COMMENT ON COLUMN inspection_report_database.id IS '系统编号';
COMMENT ON COLUMN inspection_report_database.inspection_report_id IS '巡检报表－系统编号';
COMMENT ON COLUMN inspection_report_database.datname IS '数据库名';
COMMENT ON COLUMN inspection_report_database.datcomment IS '注释';
COMMENT ON COLUMN inspection_report_database.datdba IS '所有者';
COMMENT ON COLUMN inspection_report_database.encoding IS '默认编码';
COMMENT ON COLUMN inspection_report_database.datcollate IS '排序规则';
COMMENT ON COLUMN inspection_report_database.datctype IS '分组规则';
COMMENT ON COLUMN inspection_report_database.datistemplate IS '模板数据库';
COMMENT ON COLUMN inspection_report_database.datallowconn IS '准许连接';
COMMENT ON COLUMN inspection_report_database.datconnlimit IS '最大连接数';
COMMENT ON COLUMN inspection_report_database.dattablespace IS '默认表空间';
COMMENT ON COLUMN inspection_report_database.datsize IS '占用空间';
COMMENT ON COLUMN inspection_report_database.tablenum IS '数据表数';
COMMENT ON COLUMN inspection_report_database.indexnum IS '索引数';

CREATE INDEX inspection_report_database_inspection_report_id_idx ON inspection_report_database USING BTREE(inspection_report_id);

CREATE TABLE inspection_report_table
(
	id serial not null unique,
	inspection_report_id integer not null,
	datname text not null,
	schemaname text not null,
	tablename text not null,
	tablecomment text not null,
	tableowner text not null,
	tablespace text not null,
	rownum bigint ,
	relationsize bigint not null default 0,
	indexnum int not null default 0,
	indexsize bigint not null,
	tablesize bigint not null,
	seq_scan bigint not null,
	seq_tup_read bigint not null,
	idx_scan bigint not null,
	idx_tup_fetch bigint not null,
	last_vacuum timestamp ,
	last_autovacuum timestamp,
	last_analyze timestamp,
	last_autoanalyze timestamp
);
COMMENT ON TABLE inspection_report_table IS '巡检报表--数据表统计';
COMMENT ON COLUMN inspection_report_table.id IS '系统编号';
COMMENT ON COLUMN inspection_report_table.inspection_report_id IS '巡检报表－系统编号';
COMMENT ON COLUMN inspection_report_table.datname IS '所属数据库';
COMMENT ON COLUMN inspection_report_table.schemaname IS '所属模式';
COMMENT ON COLUMN inspection_report_table.tablename IS '表名';
COMMENT ON COLUMN inspection_report_table.tablecomment IS '注释';
COMMENT ON COLUMN inspection_report_table.tableowner IS '所有者';
COMMENT ON COLUMN inspection_report_table.tablespace IS '存储表空间';
COMMENT ON COLUMN inspection_report_table.rownum IS '记录数';
COMMENT ON COLUMN inspection_report_table.relationsize IS '表文件占用空间';
COMMENT ON COLUMN inspection_report_table.indexnum IS '索引数';
COMMENT ON COLUMN inspection_report_table.indexsize IS '索引文件占用空间';
COMMENT ON COLUMN inspection_report_table.tablesize IS '表相关文件占用空间';
COMMENT ON COLUMN inspection_report_table.seq_scan IS '顺序扫描次数';
COMMENT ON COLUMN inspection_report_table.seq_tup_read IS '顺序扫描取得行数';
COMMENT ON COLUMN inspection_report_table.idx_scan IS '索引扫描次数';
COMMENT ON COLUMN inspection_report_table.idx_tup_fetch IS '索引扫描取得行数';
COMMENT ON COLUMN inspection_report_table.last_vacuum IS '手动清理时间';
COMMENT ON COLUMN inspection_report_table.last_autovacuum IS '自动清理时间';
COMMENT ON COLUMN inspection_report_table.last_analyze IS '手动分析时间';
COMMENT ON COLUMN inspection_report_table.last_autoanalyze IS '自动分析时间';

CREATE INDEX inspection_report_table_inspection_report_id_idx ON inspection_report_table USING BTREE(inspection_report_id);
CREATE INDEX inspection_report_table_tablename_idx ON inspection_report_table USING BTREE(tablename);

CREATE TABLE inspection_report_index
(
	id serial not null unique,
	inspection_report_id integer not null,
	datname text not null,
	schemaname text not null,
	tablename text not null,
	indexname text not null,
	indexcomment text not null,
	indexowner text not null,
	uniqueindex varchar(1) not null,
	tablespace text not null,
	indexsize bigint not null,
	idx_scan bigint not null,
	indexdef text not null
);
COMMENT ON TABLE inspection_report_index IS '巡检报表--索引统计';
COMMENT ON COLUMN inspection_report_index.id IS '系统编号';
COMMENT ON COLUMN inspection_report_index.inspection_report_id IS '巡检报表－系统编号';
COMMENT ON COLUMN inspection_report_index.datname IS '所属数据库';
COMMENT ON COLUMN inspection_report_index.schemaname IS '所属模式';
COMMENT ON COLUMN inspection_report_index.tablename IS '所属表名';
COMMENT ON COLUMN inspection_report_index.indexname IS '索引名';
COMMENT ON COLUMN inspection_report_index.indexcomment IS '注释';
COMMENT ON COLUMN inspection_report_index.indexowner IS '所有者';
COMMENT ON COLUMN inspection_report_index.uniqueindex IS '唯一索引';
COMMENT ON COLUMN inspection_report_index.indexsize IS '占用空间';
COMMENT ON COLUMN inspection_report_index.tablespace IS '存储表空间';
COMMENT ON COLUMN inspection_report_index.idx_scan IS '索引扫描次数';
COMMENT ON COLUMN inspection_report_index.indexdef IS '索引定义';


CREATE INDEX inspection_report_index_inspection_report_id_idx ON inspection_report_index USING BTREE(inspection_report_id);
CREATE INDEX inspection_report_index_tablename_idx ON inspection_report_index USING BTREE(tablename);

CREATE TABLE inspection_report_state
(
	id serial not null unique,
	inspection_report_id integer not null,
	subject text not null,
	val text not null
);

COMMENT ON TABLE inspection_report_state IS '巡检报表--状态统计';
COMMENT ON COLUMN inspection_report_state.id IS '系统编号';
COMMENT ON COLUMN inspection_report_state.inspection_report_id IS '巡检报表－系统编号';
COMMENT ON COLUMN inspection_report_state.subject IS '项目名称';
COMMENT ON COLUMN inspection_report_state.val IS '统计值';

CREATE INDEX inspection_report_state_inspection_report_id_idx ON inspection_report_state USING BTREE(inspection_report_id);

COMMENT ON DATABASE pgcluster IS 'postgresql集群管理器';		




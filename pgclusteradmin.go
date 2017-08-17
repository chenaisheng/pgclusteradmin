package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/astaxie/session"
	_ "github.com/astaxie/session/providers/memory"
	"github.com/jackc/pgx"
	"github.com/tealeg/xlsx"
	"golang.org/x/crypto/ssh"
)

var globalSessions *session.Manager

//程序执行结果信息json结构
type Result struct {
	Return_code       string `json:"return_code"`
	Return_msg        string `json:"return_msg"`
	Show_login_dialog int    `json:"show_login_dialog"`
}

//节点行信息json结构
type Row struct {
	Json_id                int    `json:"json_id"`
	Id                     int    `json:"id"`
	Node_name              string `json:"node_name"`
	Createtime             string `json:"createtime"`
	Service_type           string `json:"service_type"`
	Service_status         string `json:"service_status"`
	Pg_version             string `json:"pg_version"`
	Host                   string `json:"host"`
	Ssh_port               int    `json:"ssh_port"`
	Ssh_user               string `json:"ssh_user"`
	Ssh_password           string `json:"ssh_password"`
	Ssh_authmethod         string `json:"ssh_authmethod"`
	Pg_bin                 string `json:"pg_bin"`
	Pg_data                string `json:"pg_data"`
	Pg_log                 string `json:"pg_log"`
	Pg_port                uint16 `json:"pg_port"`
	Pg_database            string `json:"pg_database"`
	Pg_user                string `json:"pg_user"`
	Pg_password            string `json:"pg_password"`
	Master_vip             string `json:"master_vip"`
	Master_vip_networkcard string `json:"master_vip_networkcard"`
	Slave_vip              string `json:"slave_vip"`
	Slave_vip_networkcard  string `json:"slave_vip_networkcard"`
	Bind_vip_user          string `json:"bind_vip_user"`
	Bind_vip_password      string `json:"bind_vip_password"`
	Bind_vip_authmethod    string `json:"bind_vip_authmethod"`
	Remark                 string `json:"remark"`
	Return_code            string `json:"return_code"`
	Return_msg             string `json:"return_msg"`
}

//节点记录集json结构

type Data struct {
	Total int   `json:"total"`
	Rows  []Row `json:"rows"`
}

//ssh执行命令结果返回

type Stdout_and_stderr struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

//操作服务(启动，重启和关闭)结果信息json结构
type Result_serviceadmin struct {
	Return_code       string `json:"return_code"`
	Return_msg        string `json:"return_msg"`
	Show_login_dialog int    `json:"show_login_dialog"`
	Service_type      string `json:"service_type"`
	Service_status    string `json:"service_status"`
	Pg_version        string `json:"pg_version"`
}

//SESSION在init函数中初始化
func init() {
	globalSessions, _ = session.NewManager("memory", "gosessionid", 3600)
	go globalSessions.GC()
}

/*
功能描述：应用程序入口函数

参数说明：无

返回值说明：无
*/

func main() {

	//设置静态资源存入路径
	http.Handle("/", http.FileServer(http.Dir("./easyui/")))

	//操作登录
	http.HandleFunc("/login/", loginHandler)
	//操作员修改密码
	http.HandleFunc("/password_update/", password_updateHandler)
	//用户退出登录状态
	http.HandleFunc("/exit/", exitHandler)
	//验证操作员是否登录过
	http.HandleFunc("/logincheck/", logincheckHandler)

	//返回节点信息
	http.HandleFunc("/getnoderows/", getnoderowsHandler)

	//修改节点信息
	http.HandleFunc("/updatenode/", updatenodeHandler)
	//增加节点信息
	http.HandleFunc("/insertnode/", insertnodeHandler)
	//删除节点信息
	http.HandleFunc("/deletenode/", deletenodeHandler)

	//参数管理--获取配置文件的内容
	http.HandleFunc("/parameter_get_file_contents/", parameter_get_file_contentsHandler)
	//获取备份或模板的文件列表
	http.HandleFunc("/parameter_bak_template_list/", parameter_bak_template_listHandler)
	//获取历史或模板文件内容
	http.HandleFunc("/parameter_get_bak_template_contents/", parameter_get_bak_template_contentsHandler)
	//删除历史或模板文件
	http.HandleFunc("/parameter_files_bak_template_delete/", parameter_files_bak_template_deleteHandler)

	//提交参数
	http.HandleFunc("/parameter_save/", parameter_saveHandler)

	//start服务
	http.HandleFunc("/servicestart/", servicestartHandler)
	//stop服务
	http.HandleFunc("/servicestop/", servicestopHandler)
	//restart服务
	http.HandleFunc("/servicerestart/", servicerestartHandler)
	//reload服务
	http.HandleFunc("/servicereload/", servicereloadHandler)
	//显示服务status
	http.HandleFunc("/servicestatus/", servicestatusHandler)

	//vip管理
	http.HandleFunc("/vipadmin/", vipadminHandler)
	//备机唤醒管理
	http.HandleFunc("/slave_wakeup/", slave_wakeupHandler)

	//获取节点ip绑定情况
	http.HandleFunc("/get_ip_bind_status/", get_ip_bind_statusHandler)

	//主备切换
	http.HandleFunc("/promote/", promoteHandler)
	//主备切换弹出窗口时获取主备节点的ip绑定情况
	http.HandleFunc("/promote_get_ip_bind_status/", promote_get_ip_bind_statusHandler)

	//生成巡检报告
	http.HandleFunc("/inspection_report_make/", inspection_report_makeHandler)
	//巡检报告列表
	http.HandleFunc("/inspection_report_list/", inspection_report_listHandler)
	//巡检报告－－状态
	http.HandleFunc("/inspection_report_state_list/", inspection_report_state_listHandler)
	//巡检报告－－表空间
	http.HandleFunc("/inspection_report_tablespace_list/", inspection_report_tablespace_listHandler)
	//巡检报告－－角色
	http.HandleFunc("/inspection_report_role_list/", inspection_report_role_listHandler)
	//巡检报告－－数据库
	http.HandleFunc("/inspection_report_database_list/", inspection_report_database_listHandler)
	//巡检报告－－数据表
	http.HandleFunc("/inspection_report_table_list/", inspection_report_table_listHandler)
	//巡检报告－－外部表
	http.HandleFunc("/inspection_report_foreign_table_list/", inspection_report_foreign_table_listHandler)
	//巡检报告－－索引
	http.HandleFunc("/inspection_report_index_list/", inspection_report_index_listHandler)
	//修改巡检报告名称
	http.HandleFunc("/inspection_report_update/", inspection_report_updateHandler)
	//删除巡检报告
	http.HandleFunc("/inspection_report_delete/", inspection_report_deleteHandler)
	//导出巡检报告
	http.HandleFunc("/inspection_report_export/", inspection_report_exportHandler)
	//获取数据库列表
	http.HandleFunc("/get_database_list/", get_database_listHandler)

	//管理工具－－进程管理－－获取某个数据库或所有数据库的进程列表
	http.HandleFunc("/processadmin_process_list/", processadmin_process_listHandler)
	//管理工具－－进程管理－－取消查询
	http.HandleFunc("/processadmin_cancelquery/", processadmin_cancelqueryHandler)
	//管理工具－－进程管理－－杀死进程
	http.HandleFunc("/processadmin_killprocess/", processadmin_killprocessHandler)

	//管理工具－－表锁管理－－获取某个数据库或所有数据库的受阻塞锁列表
	http.HandleFunc("/lockadmin_lock_list/", lockadmin_lock_listHandler)
	//管理工具－－表锁管理－－获取阻塞某个进程的锁列表
	http.HandleFunc("/lockadmin_cloglock_list/", lockadmin_cloglock_listHandler)
	//管理工具－－表锁管理－－取消查询
	http.HandleFunc("/lockadmin_cancelquery/", lockadmin_cancelqueryHandler)
	//管理工具－－表锁管理－－杀死进程
	http.HandleFunc("/lockadmin_killprocess/", lockadmin_killprocessHandler)

	//管理工具－－查询统计－－获取某个数据库或所有数据库的查询统计列表
	http.HandleFunc("/querycount_record_list/", querycount_record_listHandler)
	//管理工具－－查询统计－－检测节点是否加载了pg_stat_statments模块
	http.HandleFunc("/querycount_pg_stat_statments_load_check/", querycount_pg_stat_statments_load_checkHandler)
	//管理工具－－查询统计－－查询重新统计
	http.HandleFunc("/querycount_dialog_countreset/", querycount_dialog_countresetHandler)

	http.ListenAndServe(":10001", nil)

}

/*
功能描述：操作员登录

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "loginHandler"
	username := r.FormValue("username")
	if r.FormValue("username") == "" {
		error_msg = "非法访问，用户名不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	if r.FormValue("password") == "" {
		error_msg = "非法访问，密码不能不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	//开启session
	sess := globalSessions.SessionStart(w, r)
	//连接数据库
	var conn *pgx.Conn
	conn, err := pgx.Connect(extractConfig())
	if err != nil {
		error_msg = "连接db失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	//验证用户是否合法
	sql := "SELECT username FROM users WHERE username=$1 AND password=md5($2)"
	rows, err := conn.Query(sql, r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer rows.Close()

	if rows.Next() {
		sess.Set("username", r.FormValue("username"))
		error_msg = "验证通过"
		OutputJson(w, "SUCCESS", error_msg, 0)
	} else {
		error_msg = "验证无法通过"
		OutputJson(w, "FAIL", error_msg, 0)
	}
	go write_log(remote_ip, modlename, username, "Log", error_msg)
	return
}

/*
功能描述：操作员修改密码

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func password_updateHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "password_update"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	if r.FormValue("new_password") == "" {
		error_msg = "非法访问，新的密码不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	if r.FormValue("new_password") != r.FormValue("new_password_confirm") {
		error_msg = "非法访问，新密码不一致"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	//连接数据库
	var conn *pgx.Conn
	conn, err := pgx.Connect(extractConfig())
	if err != nil {
		error_msg = "连接db失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	//验证用户是否合法
	sql := "UPDATE users SET password=md5($1) WHERE username=$2 AND password=md5($3) RETURNING username"
	rows, err := conn.Query(sql, r.FormValue("new_password"), username, r.FormValue("old_password"))
	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer rows.Close()

	if rows.Next() {
		error_msg = "修改密码成功"
		OutputJson(w, "SUCCESS", error_msg, 0)
	} else {
		error_msg = "旧密码不正确，修改失败"
		OutputJson(w, "FAIL", error_msg, 0)
	}
	go write_log(remote_ip, modlename, username, "Log", error_msg)
	return
}

/*
功能描述：用户退出登录状态

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func exitHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "exitHandler"
	//开启session
	sess := globalSessions.SessionStart(w, r)
	username := fmt.Sprintf("%v", sess.Get("username"))
	err := sess.Delete("username")

	if err == nil {
		error_msg = "你已经安全退出系统"
		OutputJson(w, "SUCCESS", error_msg, 0)
	} else {
		error_msg = "退出出错，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
	}
	go write_log(remote_ip, modlename, username, "Log", error_msg)
	return
}

/*
功能描述：验证操作员是否登录过

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func logincheckHandler(w http.ResponseWriter, r *http.Request) {
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "验证未通过", 0)
	} else {
		OutputJson(w, "SUCCESS", "验证通过", 0)
	}
	return
}

/*
功能描述：返回节点信息

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func getnoderowsHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "getnoderowsHandler"
	username := http_init(w, r)
	if username == "" {
		//OutputJson(w,"FAIL","系统无法识别你的身份",0)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	conn, err := pgx.Connect(extractConfig())
	if err != nil {
		error_msg = "连接db失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql := `
    SELECT 
        id,node_name,
        createtime::text,
        host,ssh_port,
		ssh_authmethod,ssh_user,
        ssh_password,pg_bin,
        pg_data,pg_log,
		pg_port,pg_database,
		pg_user,pg_password,
        master_vip,master_vip_networkcard,
        slave_vip,slave_vip_networkcard,    
		bind_vip_authmethod,
        bind_vip_user,bind_vip_password,     
        remark 
    FROM 
        nodes 
    ` + sql_sort_limit(r)

	rows, err := conn.Query(sql)
	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	var data Data = Data{}
	data.Rows = make([]Row, 0)
	data.Total = 0
	end := make(chan Row)
	for rows.Next() {
		var row Row
		err = rows.Scan(
			&row.Id, &row.Node_name,
			&row.Createtime,
			&row.Host, &row.Ssh_port,
			&row.Ssh_authmethod, &row.Ssh_user,
			&row.Ssh_password, &row.Pg_bin,
			&row.Pg_data, &row.Pg_log,
			&row.Pg_port, &row.Pg_database,
			&row.Pg_user, &row.Pg_password,
			&row.Master_vip, &row.Master_vip_networkcard,
			&row.Slave_vip, &row.Slave_vip_networkcard,
			&row.Bind_vip_authmethod,
			&row.Bind_vip_user, &row.Bind_vip_password,
			&row.Remark)
		if err != nil {
			error_msg = "执行查询失败，详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		//获取节点的类型和目前服务状态，主节点还是备节点。
		row.Json_id = data.Total
		data.Rows = append(data.Rows, row)
		go getnode_type_and_status(end, data.Rows[data.Total])
		data.Total = data.Total + 1
	}
	rows.Close()

	for i := 0; i < data.Total; i++ {
		t := <-end
		data.Rows[t.Json_id].Service_type = t.Service_type
		data.Rows[t.Json_id].Service_status = t.Service_status
		data.Rows[t.Json_id].Pg_version = t.Pg_version
	}

	//统计总记录数
	sql = "SELECT COUNT(1) AS num FROM nodes"
	rows, err = conn.Query(sql)
	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	if rows.Next() {
		err = rows.Scan(&data.Total)
		if err != nil {
			error_msg = "执行查询失败，详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}
	rows.Close()

	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：获回节点类型、状态及版本信息，值直接付给row属性

先用数据库参数连接获取 节点类型、状态及版本信息 ，如果数据库服务获取失败再用pg_controldata获取

参数说明：
row -- Row

返回值说明：
end -- chan Row
*/

func getnode_type_and_status(end chan Row, row Row) {
	//初始化
	row.Service_status = ""
	row.Service_type = ""
	row.Pg_version = ""
	//定义要连接数据库参数
	var config pgx.ConnConfig
	config.Host = row.Host
	config.User = row.Pg_user
	config.Password = row.Pg_password
	config.Database = row.Pg_database
	config.Port = row.Pg_port

	//连接数据库
	var conn *pgx.Conn
	conn, err := pgx.Connect(config)
	if err == nil {
		defer conn.Close()
		row.Service_status = "运行中"
		sql := "SELECT CASE WHEN current_setting('wal_level') in ('minimal','archive') THEN '普通节点'  WHEN pg_is_in_recovery() THEN '备节点' ELSE '主节点' END AS service_type,version() as pg_version"
		rows, err := conn.Query(sql)
		if err != nil {
			row.Service_type = "获取节点类型出错"
			row.Pg_version = "获取版本号出错" + err.Error()
			end <- row
			return
		}
		defer rows.Close()
		if rows.Next() {
			var service_type string
			var pg_version string
			err = rows.Scan(&service_type, &pg_version)
			if err != nil {
				row.Service_type = "获取节点类型出错"
				row.Pg_version = "获取版本号出错：" + err.Error()
				end <- row
				return
			}
			row.Service_type = service_type
			row.Pg_version = pg_version
			end <- row
			return
		}
	} else {
		row.Service_status = "服务停止"
		//远程登录，使用 pg_controldata 工具获取
		cmd := row.Pg_bin + "pg_controldata " + row.Pg_data
		stdout, stderr := ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
		if stderr != "" {
			row.Service_status = "无法获得节点状态，详情：" + stderr
			end <- row
			return
		}
		if strings.Contains(stdout, "shut down in recovery") {
			row.Service_status = "服务停止"
			row.Service_type = "备节点"
		} else if strings.Contains(stdout, "in archive recovery") {
			//需要检查port是否已经存在,存在表示运行中,备机启动失败后会保留这个状态"in archive recovery"
			cmd = "netstat -tunlp |grep " + fmt.Sprintf("%d", row.Pg_port)
			status_out_chan := make(chan Stdout_and_stderr)
			go ssh_run_chan(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd, status_out_chan)
			status_out := <-status_out_chan
			if status_out.Stdout != "" {
				row.Service_status = "运行中"
			} else {
				row.Service_status = "服务停止"
			}
			row.Service_type = "备节点"
		} else if strings.Contains(stdout, "shut down") {
			row.Service_status = "服务停止"
			row.Service_type = "主节点"
		} else if strings.Contains(stdout, "in production") {
			//需要检查port是否已经存在,存在表示运行中。有一种情况是使用pg_basebackup复制后,如果没启动过,则这个值是"in production"
			cmd = "netstat -tunlp |grep " + fmt.Sprintf("%d", row.Pg_port)
			status_out_chan := make(chan Stdout_and_stderr)
			go ssh_run_chan(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd, status_out_chan)

			//需要检查recovery.conf是否已经存在,存在表示是备节点
			cmd = "ls " + row.Pg_data + "recovery.conf"
			type_out_chan := make(chan Stdout_and_stderr)
			go ssh_run_chan(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd, type_out_chan)

			status_out := <-status_out_chan
			if status_out.Stdout != "" {
				row.Service_status = "运行中"
			} else {
				row.Service_status = "服务停止"
			}

			type_out := <-type_out_chan
			if type_out.Stdout != "" {
				row.Service_type = "备节点"
			} else {
				row.Service_type = "主节点"
			}
		} else if strings.Contains(stdout, "minimal") || strings.Contains(stdout, "archive") {
			row.Service_type = "普通节点"
			if strings.Contains(stdout, "shut down") {
				row.Service_status = "服务停止"
			} else {
				row.Service_status = "运行中"
			}
		} else {
			row.Service_status = "无法识别"
			row.Service_type = "无法识别"
		}
		//获取pg的版本号
		lines := strings.Split(stdout, "\n")
		row.Pg_version = lines[0]
		end <- row
	}
}

/*
功能描述：增加节点资料

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func insertnodeHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "insertnodeHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	if r.FormValue("master_vip") != "" && !str_is_ip(r.FormValue("master_vip")) {
		error_msg = "做为主节点绑定VIP[" + r.FormValue("master_vip") + "]不是合法的ip地址"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("slave_vip") != "" && !str_is_ip(r.FormValue("slave_vip")) {
		error_msg = "做为备节点绑定VIP[" + r.FormValue("master_vip") + "]不是合法的ip地址"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("ssh_authmethod") != "key" && r.FormValue("ssh_authmethod") != "password" {
		error_msg = "非法的ssh_authmethod值 [ " + r.FormValue("ssh_authmethod") + " ] "
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("bind_vip_authmethod") != "key" && r.FormValue("bind_vip_authmethod") != "password" {
		error_msg = "非法的bind_vip_authmethod值 [ " + r.FormValue("bind_vip_authmethod") + " ] "
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	conn, err := pgx.Connect(extractConfig())
	if err != nil {
		error_msg = "连接db失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	//检查节点是否已经存在,node_name不能相同
	sql := " SELECT id FROM nodes WHERE node_name = $1 "
	rows, err := conn.Query(sql, r.FormValue("node_name"))
	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if rows.Next() {
		OutputJson(w, "FAIL", "节点名称已经被使用", 0)
		return
	}
	rows.Close()

	//检查节点是否已经存在,host + pg_port 不能相同
	sql = " SELECT id FROM nodes WHERE host = $1 AND pg_port = $2 "
	rows, err = conn.Query(sql, r.FormValue("host"), r.FormValue("pg_port"))
	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if rows.Next() {
		OutputJson(w, "FAIL", "主机名+数据库端口号已经存在", 0)
		return
	}
	rows.Close()

	//检查节点是否已经存在,host + pg_data 不能相同
	sql = " SELECT id FROM nodes WHERE host = $1 AND pg_data = $2 "
	rows, err = conn.Query(sql, r.FormValue("host"), r.FormValue("pg_data"))
	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if rows.Next() {
		OutputJson(w, "FAIL", "主机名+data路径已经存在", 0)
		return
	}
	rows.Close()

	sql = `
    INSERT INTO nodes
    (
        node_name, 
		host,ssh_port,
		ssh_authmethod,
		ssh_user,ssh_password, 
        pg_bin,pg_data,
        pg_log,pg_port,
        pg_database, pg_user,
        pg_password, remark,
        master_vip, master_vip_networkcard,
        slave_vip, slave_vip_networkcard,    
		bind_vip_authmethod,
        bind_vip_user, bind_vip_password
    ) 
    VALUES
    (   
        $1, 
		$2,  $3,
		$4,
		$5,  $6,
        $7,  $8,
        $9,  $10,
		$11, $12,
		$13, $14,
		$15, $16,
		$17, $18,
		$19,
		$20, $21
    ) returning id    
    `
	rows, err = conn.Query(sql,
		r.FormValue("node_name"),
		r.FormValue("host"), r.FormValue("ssh_port"),
		r.FormValue("ssh_authmethod"),
		r.FormValue("ssh_user"), r.FormValue("ssh_password"),
		r.FormValue("pg_bin"), r.FormValue("pg_data"),
		r.FormValue("pg_log"), r.FormValue("pg_port"),
		r.FormValue("pg_database"), r.FormValue("pg_user"),
		r.FormValue("pg_password"), r.FormValue("remark"),
		r.FormValue("master_vip"), r.FormValue("master_vip_networkcard"),
		r.FormValue("slave_vip"), r.FormValue("slave_vip_networkcard"),
		r.FormValue("bind_vip_authmethod"),
		r.FormValue("bind_vip_user"), r.FormValue("bind_vip_password"))

	if err != nil {
		error_msg = "增加节点资料失败,详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	} else {
		if rows.Next() {
			var node_id int
			err = rows.Scan(&node_id)
			if err != nil {
				error_msg = "增加节点资料失败,详情：" + err.Error()
				OutputJson(w, "FAIL", error_msg, 0)
				go write_log(remote_ip, modlename, username, "Error", error_msg)
				return
			}
			go write_log(remote_ip, modlename, username, "Log", "增加节点资料成功,id号为："+fmt.Sprintf("%d", node_id))
			OutputJson(w, "SUCCESS", "增加节点资料成功", 0)
		} else {
			error_msg = "增加节点资料失败,无法获取新增节点的id号"
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}
}

/*
功能描述：修改节点资料

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func updatenodeHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "updatenodeHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//检查要修改的node_id是否合法
	if !str_is_int(r.FormValue("id")) {
		error_msg = "非法的node_id号 [ " + r.FormValue("id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("master_vip") != "" && !str_is_ip(r.FormValue("master_vip")) {
		error_msg = "做为主节点绑定VIP[" + r.FormValue("master_vip") + "]不是合法的ip地址"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("slave_vip") != "" && !str_is_ip(r.FormValue("slave_vip")) {
		error_msg = "做为备节点绑定VIP[" + r.FormValue("master_vip") + "]不是合法的ip地址"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("ssh_authmethod") != "key" && r.FormValue("ssh_authmethod") != "password" {
		error_msg = "非法的ssh_authmethod值 [ " + r.FormValue("ssh_authmethod") + " ] "
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("bind_vip_authmethod") != "key" && r.FormValue("bind_vip_authmethod") != "password" {
		error_msg = "非法的bind_vip_authmethod值 [ " + r.FormValue("bind_vip_authmethod") + " ] "
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	conn, err := pgx.Connect(extractConfig())
	if err != nil {
		error_msg = "连接db失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	//检查节点是否已经存在
	sql := " SELECT id FROM nodes WHERE node_name=$1 AND id != $2 "
	rows, err := conn.Query(sql, r.FormValue("node_name"), r.FormValue("id"))
	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	if rows.Next() {
		OutputJson(w, "FAIL", "节点名称已经被使用", 0)
		return
	}
	rows.Close()

	//检查节点是否已经存在,host + pg_port 不能相同
	sql = " SELECT id FROM nodes WHERE host = $1 AND pg_port = $2 AND id != $3 "
	rows, err = conn.Query(sql, r.FormValue("host"), r.FormValue("pg_port"), r.FormValue("id"))
	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	if rows.Next() {
		OutputJson(w, "FAIL", "主机名+数据库端口号已经存在", 0)
		return
	}
	rows.Close()

	//检查节点是否已经存在,host + pg_data 不能相同
	sql = " SELECT id FROM nodes WHERE host = $1 AND pg_data = $2 AND id != $3 "
	rows, err = conn.Query(sql, r.FormValue("host"), r.FormValue("pg_data"), r.FormValue("id"))
	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	if rows.Next() {
		OutputJson(w, "FAIL", "主机名+data路径已经存在", 0)
		return
	}
	rows.Close()

	sql = `
    UPDATE 
        nodes 
    SET 
        node_name=$1,
        host=$2, ssh_port=$3,
		ssh_authmethod=$4,
        ssh_user=$5, ssh_password=$6,
        pg_bin=$7, pg_data=$8,
        pg_port=$9, pg_database=$10,
        pg_user=$11, pg_password=$12,
        remark=$13, pg_log=$14,
        master_vip=$15, master_vip_networkcard=$16,
        slave_vip=$17, slave_vip_networkcard=$18, 
		bind_vip_authmethod =$19,    
        bind_vip_user=$20, bind_vip_password=$21 
    WHERE 
        id=$22
    `
	_, err = conn.Exec(sql,
		r.FormValue("node_name"),
		r.FormValue("host"), r.FormValue("ssh_port"),
		r.FormValue("ssh_authmethod"),
		r.FormValue("ssh_user"), r.FormValue("ssh_password"),
		r.FormValue("pg_bin"), r.FormValue("pg_data"),
		r.FormValue("pg_port"), r.FormValue("pg_database"),
		r.FormValue("pg_user"), r.FormValue("pg_password"),
		r.FormValue("remark"), r.FormValue("pg_log"),
		r.FormValue("master_vip"), r.FormValue("master_vip_networkcard"),
		r.FormValue("slave_vip"), r.FormValue("slave_vip_networkcard"),
		r.FormValue("bind_vip_authmethod"),
		r.FormValue("bind_vip_user"), r.FormValue("bind_vip_password"),
		r.FormValue("id"))

	if err != nil {
		error_msg = "修改节点资料失败,详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	} else {
		OutputJson(w, "SUCCESS", "修改资料保存成功", 0)
		go write_log(remote_ip, modlename, username, "Log", "修改节点资料成功,id号为："+r.FormValue("id"))
		return
	}
}

/*
功能描述：删除节点信息

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func deletenodeHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "deletenodeHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//检查要修改的node_id是否合法
	if !str_is_int(r.FormValue("id")) {
		error_msg = "非法的node_id号 [ " + r.FormValue("id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	conn, err := pgx.Connect(extractConfig())
	if err != nil {
		error_msg = "连接db失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql := "DELETE FROM nodes WHERE id = $1 returning node_name "
	rows, err := conn.Query(sql, r.FormValue("id"))

	if err != nil {
		error_msg = "删除节点资料失败,详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	} else {
		if rows.Next() {
			var node_name string
			err = rows.Scan(&node_name)
			if err != nil {
				error_msg = "删除节点资料失败,详情：" + err.Error()
				OutputJson(w, "FAIL", error_msg, 0)
				go write_log(remote_ip, modlename, username, "Error", error_msg)
				return
			}
			go write_log(remote_ip, modlename, username, "Log", "删除节点资料成功,id号为 [ "+r.FormValue("id")+" ] ，node_name为 [ "+node_name+" ]")
			OutputJson(w, "SUCCESS", "删除节点资料成功", 0)
		} else {
			error_msg = "删除节点资料成功"
			OutputJson(w, "SUCCESS", error_msg, 0)
			return
		}
	}
}

/*
功能描述：start服务

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func servicestartHandler(w http.ResponseWriter, r *http.Request) {
	serviceadminHandler(w, r, "start")
}

/*
功能描述：stop服务

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func servicestopHandler(w http.ResponseWriter, r *http.Request) {
	serviceadminHandler(w, r, "stop")
}

/*
功能描述：restart服务

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func servicerestartHandler(w http.ResponseWriter, r *http.Request) {
	serviceadminHandler(w, r, "restart")
}

/*
功能描述：reload服务

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func servicereloadHandler(w http.ResponseWriter, r *http.Request) {
	serviceadminHandler(w, r, "reload")
}

/*
功能描述：显示服务status

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：无
*/

func servicestatusHandler(w http.ResponseWriter, r *http.Request) {
	serviceadminHandler(w, r, "status")
}

/*
功能描述：执行服务的各种操作

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针
act -- 操作类型

返回值说明：无
*/

func serviceadminHandler(w http.ResponseWriter, r *http.Request, act string) {
	var error_msg string
	modlename := "serviceadminHandler-" + act
	remote_ip := get_remote_ip(r)
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	//判断节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = "节点id号不是合法的int类型，id号为 [ " + r.FormValue("id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	row := <-row_chan
	if row.Return_code == "FAIL" {
		error_msg = "获取节点资料失败,详情：" + row.Return_msg
		out := &Result_serviceadmin{row.Return_code, error_msg, 0, r.FormValue("service_type"), r.FormValue("service_status"), r.FormValue("pg_version")}
		b, _ := json.Marshal(out)
		w.Write(b)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//对节点执行相应的服务操作
	row = serviceadmin(row, act, r.FormValue("mode"), username)
	var logtype string
	if row.Return_code == "FAIL" {
		logtype = "Error"
	} else {
		logtype = "Log"
	}

	error_msg = row.Return_msg
	out := &Result_serviceadmin{row.Return_code, error_msg, 0, row.Service_type, row.Service_status, row.Pg_version}
	b, _ := json.Marshal(out)
	w.Write(b)
	go write_log(remote_ip, modlename, username, logtype, error_msg)

}

/*
功能描述：执行服务的各种操作

参数说明：
row   -- Row类型
act   -- 操作类型,分别是start,stop,restart,reload,status
mode  -- start或restart时的模式
username --操作用户

返回值说明：

Row  -- Row类型
*/

func serviceadmin(row Row, act string, a_mode string, username string) Row {
	row.Return_code = "FAIL"
	row.Return_msg = ""
	//判断要执行的服务类型是否存在
	if act != "start" && act != "stop" && act != "restart" && act != "reload" && act != "status" {
		row.Return_msg = "要执行的服务操作类型[ " + act + " ]不存在"
		return row
	}
	//判断mode是否正确
	if a_mode != "smart" && a_mode != "fast" && a_mode != "immediate" && (act == "stop" && act == "restart") {
		row.Return_msg = "stop或restart使用模式mode[ " + act + " ]不存在"
		return row
	}
	var mode string
	if act == "stop" || act == "restart" {
		mode = " -m " + a_mode
	} else {
		mode = ""
	}

	//如果是reload则需要去先获取主进程产生日志
	var filename string
	var cmd string
	var stdout string
	var stderr string
	var before_lines []string
	var after_lines []string
	var lines []string

	//提取reload前日志文件中系统级别错误信息
	if act == "reload" {
		//这里生成的filename要给后面使用哦，记得中间其它程序不能修改filename的值哦
		if row.Pg_log != "" {
			//reload获取postgresql主进程产生的日志
			cmd = "ls " + row.Pg_log + " '-rt'"
			stdout, stderr = ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
			if stderr != "" {
				row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + stderr
				return row
			}
			lines = strings.Split(stdout, "\n")
			filename = row.Pg_log + lines[len(lines)-2]
		} else {
			filename = row.Pg_data + username + "_logfile.txt"
		}
		cmd = "test -f " + row.Pg_data + "postmaster.pid && pid=`head -1  " + row.Pg_data + "postmaster.pid" + " `;test -f " + row.Pg_data + "postmaster.pid && test -f " + filename + " && cat " + filename + " | grep $pid"
		stdout, stderr = ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
		if stderr != "" {
			row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：" + stderr
			return row
		}
		before_lines = strings.Split(stdout, "\n")
	}

	//ssh主机并执行相应的命令
	cmd = row.Pg_bin + "pg_ctl " + act + " -D " + row.Pg_data + mode + " > " + row.Pg_data + username + "_logfile.txt;cat " + row.Pg_data + username + "_logfile.txt"
	stdout, stderr = ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)

	if act == "start" || act == "restart" {
		time.Sleep(1 * time.Second)
	}

	//重新获取节点的状态
	row_chan := make(chan Row)
	go getnode_type_and_status(row_chan, row)
	row = <-row_chan

	//当服务为Stop状态时，执行restart会有提示xxx.pid不存在的错误，但接着服务会启动，此时我们应该告诉重启成功更为准确
	if stderr != "" && (stdout == "" || act != "restart") {
		row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：" + stderr
		return row
	}

	//如果是start或者restart操作的并且操作后节点的状态处于"服务停止"
	if row.Service_status == "服务停止" && (act == "start" || act == "restart") {
		//需要判断是否有参数配置出错或者资源冲突导致数据库关闭
		cmd = "cat " + row.Pg_data + username + "_logfile.txt"
		logstdout, logstderr := ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
		if logstderr != "" {
			row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + logstdout
			return row
		}
		if strings.Contains(logstdout, "errors") || strings.Contains(logstdout, "database system is shut down") {
			row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + logstdout
			return row
		}
		//如果配置了日志重定向,则需要从日志文件检查pg_hba.conf是否配置有误
		if row.Pg_log != "" {
			cmd = "ls " + row.Pg_log + " '-rt'"
			stdout, stderr = ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
			if stderr != "" {
				row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + stderr
				return row
			}
			lines = strings.Split(stdout, "\n")
			filename = lines[len(lines)-2]

			cmd = "cat " + row.Pg_log + filename
			stdout, stderr = ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
			if stderr != "" {
				row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + stderr
				return row
			}
			row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + stdout
			return row
		}
	}
	//如果是start或者restart操作,并且节点类型为"备节点",需要判断复制进程是否连接上主机
	if row.Service_type == "备节点" && (act == "start" || act == "restart") {
		if row.Pg_log != "" {
			cmd = "ls " + row.Pg_log + " '-rt'"
			logstdout, logstderr := ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
			if logstderr != "" {
				row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + logstderr
				return row
			}
			lines = strings.Split(logstdout, "\n")
			filename = row.Pg_log + lines[len(lines)-2]
		} else {
			filename = row.Pg_data + username + "_logfile.txt"
		}
		cmd = "cat " + filename + "|grep 'could not connect to the primary server'"
		logstdout, logstderr := ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
		if logstderr != "" {
			row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + logstderr
			return row
		}
		if logstdout != "" {
			row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + logstdout
			return row
		}
	}

	//提取reload前日志文件中系统级别错误信息
	if act == "reload" {
		//reload获取postgresql主进程产生的日志
		cmd = "test -f " + row.Pg_data + "postmaster.pid && pid=`head -1  " + row.Pg_data + "postmaster.pid" + " `;test -f " + row.Pg_data + "postmaster.pid && test -f " + filename + " && cat " + filename + " | grep $pid"
		logstdout, logstderr := ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
		if stderr != "" {
			row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：" + logstderr
			return row
		}
		after_lines = strings.Split(logstdout, "\n")
		logcontent := ""
		for i := len(before_lines) - 1; i < len(after_lines); i++ {
			logcontent = logcontent + after_lines[i] + "\n"
		}

		if strings.Contains(logcontent, "error") || strings.Contains(logcontent, "not reloaded") {
			row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + logcontent
			return row
		}
	}
	//返回执行成功
	row.Return_msg = stdout
	row.Return_code = "SUCCESS"
	return row
}

/*
功能描述：参数配置--获取要配置文件的内容

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func parameter_get_file_contentsHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	modlename := "parameter_get_file_contentsHandler"
	remote_ip := get_remote_ip(r)
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//判断主节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = "节点id号不是合法的int类型，id号为 [ " + r.FormValue("id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断要获取文件名参数是否非法
	if r.FormValue("parameter_file_name") != "postgresql.conf" && r.FormValue("parameter_file_name") != "pg_hba.conf" && r.FormValue("parameter_file_name") != "recovery.conf" {
		error_msg = "要获取的文件名参数值非法 [ " + r.FormValue("parameter_file_name") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	row := <-row_chan
	if row.Return_code == "FAIL" {
		error_msg = "获取节点资料失败,详情：" + row.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	cmd := "cat " + row.Pg_data + r.FormValue("parameter_file_name")
	stdout, stderr := ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
	if stderr != "" {
		error_msg = "获取配置文件内容出错,详情：" + stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//定义返回的结构体
	type Ret struct {
		Return_code             string `json:"return_code"`
		Return_msg              string `json:"return_msg"`
		Show_login_dialog       int    `json:"show_login_dialog"`
		Parameter_file_conetens string `json:"parameter_file_conetens"`
	}

	out := &Ret{"SUCCESS", "获取成功", 0, stdout}
	b, _ := json.Marshal(out)
	w.Write(b)
}

/*
功能描述：参数配置--获取备份或模板文件列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func parameter_bak_template_listHandler(w http.ResponseWriter, r *http.Request) {
	//节点行信息json结构
	type List struct {
		Id         int    `json:"id"`
		Createtime string `json:"createtime"`
		Username   string `json:"username"`
		Version    string `json:"version"`
		Remark     string `json:"remark"`
	}

	//节点记录集json结构

	type Listdata struct {
		Total int    `json:"total"`
		Rows  []List `json:"rows"`
	}

	var error_msg string
	modlename := "parameter_bak_template_listHandler"
	remote_ip := get_remote_ip(r)
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	conn, err := pgx.Connect(extractConfig())
	if err != nil {
		error_msg = "连接db失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql := ""
	var rows *pgx.Rows

	if r.FormValue("category") == "bak" {
		sql = `
	    SELECT 
	        id,createtime::text,
	        username,version,
			remark
	    FROM 
	        parameter_bak_template 
		WHERE
			nodeid = $1
			AND filename = $2
			AND category = 'bak'
		ORDER BY
		    createtime DESC
	    `
		rows, err = conn.Query(sql, r.FormValue("id"), r.FormValue("filename"))
	} else {
		sql = `
	    SELECT 
	        id,createtime::text,
	        username,version,
			remark
	    FROM 
	        parameter_bak_template 
		WHERE
			filename = $1
			AND category = 'template'
		ORDER BY
		    createtime DESC
	    `
		rows, err = conn.Query(sql, r.FormValue("filename"))
	}

	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer rows.Close()

	var data Listdata = Listdata{}
	data.Rows = make([]List, 0)
	data.Total = 0
	for rows.Next() {
		var row List
		err = rows.Scan(&row.Id, &row.Createtime, &row.Username, &row.Version, &row.Remark)
		if err != nil {
			error_msg = "执行查询失败，详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		data.Rows = append(data.Rows, row)
		data.Total = data.Total + 1
	}
	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：参数配置--获取要历史文件的内容

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func parameter_get_bak_template_contentsHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	modlename := "parameter_get_bak_template_contentsHandler"
	remote_ip := get_remote_ip(r)
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//判断主节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = "节点id号不是合法的int类型，id号为 [ " + r.FormValue("id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		error_msg = "连接db失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql := `
    SELECT 
        content
    FROM 
        parameter_bak_template
    WHERE
	    id = $1 
    `

	rows, err := conn.Query(sql, id)
	if err != nil {
		error_msg = "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer rows.Close()

	var content string
	if rows.Next() {
		err = rows.Scan(&content)
		if err != nil {
			error_msg = "执行查询失败，详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//定义返回的结构体
	type Ret struct {
		Return_code             string `json:"return_code"`
		Return_msg              string `json:"return_msg"`
		Show_login_dialog       int    `json:"show_login_dialog"`
		Parameter_file_conetens string `json:"parameter_file_conetens"`
	}

	out := &Ret{"SUCCESS", "获取成功", 0, content}
	b, _ := json.Marshal(out)
	w.Write(b)
}

/*
功能描述：删除历史文件或模板文件

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func parameter_files_bak_template_deleteHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	modlename := "parameter_files_bak_template_deleteHandler"
	remote_ip := get_remote_ip(r)
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	conn, err := pgx.Connect(extractConfig())
	if err != nil {
		error_msg = "连接db失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql := "DELETE FROM parameter_bak_template WHERE id = $1 RETURNING content"
	row, err := conn.Query(sql, r.FormValue("id"))
	if err != nil {
		error_msg = "删除失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	content := ""
	if row.Next() {
		err = row.Scan(&content)
		if err != nil {
			error_msg = "删除失败,详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		OutputJson(w, "SUCCESS", "执行成功！", 0)
		go write_log(remote_ip, modlename, username, "Log", content)

	} else {
		OutputJson(w, "SUCCESS", "执行成功！", 0)
	}
	return
}

/*
功能描述：参数配置--提交参数,提交后可以只保存,可以reload,也可以restart，另外也可以保存为模板，给后面其它节点使用

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func parameter_saveHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	modlename := "parameter_saveHandler"
	remote_ip := get_remote_ip(r)
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//判断主节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = "节点id号不是合法的int类型，id号为 [ " + r.FormValue("id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断要获取文件名参数是否非法
	if r.FormValue("parameter_file_name") != "postgresql.conf" && r.FormValue("parameter_file_name") != "pg_hba.conf" && r.FormValue("parameter_file_name") != "recovery.conf" {
		error_msg = "要获取的文件名参数值非法 [ " + r.FormValue("parameter_file_name") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断act值是否非法
	if r.FormValue("act") != "save" && r.FormValue("act") != "reload" && r.FormValue("act") != "restart" && r.FormValue("act") != "saveas_template" {
		error_msg = "执行方式值非法 [ " + r.FormValue("act") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	row := <-row_chan
	if row.Return_code == "FAIL" {
		error_msg = "获取节点资料失败,详情：" + row.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//另存为模板
	if r.FormValue("act") == "saveas_template" {
		go parameter_save_bak_template(id, username, r.FormValue("parameter_file_name"), r.FormValue("parameter_file_contents"), "template", r.FormValue("remark"), remote_ip, row)
		logcontent := "另存为模板成功\nnode_id [ " + r.FormValue("id") + " ]\n参数文件[ " + r.FormValue("parameter_file_name") + " ]\n写入内容 [ " + r.FormValue("parameter_file_contents") + " ]"
		go write_log(remote_ip, modlename, username, "Log", logcontent)
		OutputJson(w, "SUCCESS", "执行成功！", 0)
		return
	}

	parameter_file_name := row.Pg_data + r.FormValue("parameter_file_name")
	cmd := "cp " + parameter_file_name + " " + parameter_file_name + ".pgclusteradmin.bak"
	cmd = cmd + ";echo \"" + r.FormValue("parameter_file_contents") + "\" > " + parameter_file_name
	cmd = cmd + ";cat " + parameter_file_name + ".pgclusteradmin.bak"

	stdout, stderr := ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
	if stderr != "" {
		error_msg = "保存配置文件内容出错,详情：" + stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	//备份参数文件
	go parameter_save_bak_template(id, username, r.FormValue("parameter_file_name"), stdout, "bak", r.FormValue("remark"), remote_ip, row)

	logcontent := "保存成功\nnode_id [ " + r.FormValue("id") + " ]\n参数文件[ " + r.FormValue("parameter_file_name") + " ]\n写入内容 [ " + r.FormValue("parameter_file_contents") + " ]"
	if r.FormValue("act") == "save" {
		OutputJson(w, "SUCCESS", "执行成功！", 0)
		go write_log(remote_ip, modlename, username, "Log", logcontent)
		return
	}
	//判断是否需要reload或者restart
	if r.FormValue("act") == "reload" || r.FormValue("act") == "restart" {
		row = serviceadmin(row, r.FormValue("act"), "fast", username)
		var logtype string
		if row.Return_code == "FAIL" {
			logtype = "Error"
			error_msg = row.Return_msg
		} else {
			logtype = "Log"
			error_msg = logcontent
		}
		out := &Result_serviceadmin{row.Return_code, row.Return_msg, 0, row.Service_type, row.Service_status, row.Pg_version}
		b, _ := json.Marshal(out)
		w.Write(b)
		go write_log(remote_ip, modlename, username, logtype, error_msg)
		return
	}
}

/*
功能描述：备份配置文件，使用go routine调用

参数说明：
nodeid    -- 节点id号
username  -- 操作员
filename  -- 配置文件名
content   -- 配置文件内容
category  -- 类别bak或template
remark    -- 备注
remote_ip -- 访问ip
row       -- Row结构类型
返回值说明：无
*/

func parameter_save_bak_template(nodeid int, username string, filename string, content string, category string, remark string, remote_ip string, row Row) {
	var error_msg string
	modlename := "parameter_save_bak_template"

	//连接数据库
	var conn *pgx.Conn
	conn, err := pgx.Connect(extractConfig())
	if err != nil {
		error_msg = "连接db失败，详情：" + err.Error()
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	//获取节点的状态,其中包含了版本号
	row_chan := make(chan Row)
	go getnode_type_and_status(row_chan, row)
	row = <-row_chan

	sql := `
    INSERT INTO parameter_bak_template
    (
        nodeid, createtime,
		username, filename,
		version,content,
		category,remark
    ) 
    VALUES
    (   
        $1, now(),
        $2, $3,
        $4, $5,
		$6, $7
	)
    `
	_, err = conn.Exec(sql,
		nodeid,
		username, filename,
		row.Pg_version, content,
		category, remark)
}

/*
功能描述：vip管理,绑定和解绑ip

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func vipadminHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	modlename := "vipadminHandler"
	remote_ip := get_remote_ip(r)
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//判断节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = "节点id号不是合法的int类型，id号为 [ " + r.FormValue("id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//检查act的合法性
	if r.FormValue("act") != "bind" && r.FormValue("act") != "unbind" {
		error_msg = "非法的act值 [ " + r.FormValue("act") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断要操作的VIP地址是否为合法的IP地址
	if !str_is_ip(r.FormValue("vip")) {
		error_msg = "VIP[" + r.FormValue("vip") + "]不是合法的ip地址"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	//判断设备号是否为空
	if r.FormValue("vip_networkcard") == "" {
		error_msg = "网卡设备号不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	//判断绑定操作用户名是否为空
	if r.FormValue("bind_vip_user") == "" {
		error_msg = "绑定操作用户名不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断bind_vip_authmethod字符值是否合法
	if r.FormValue("bind_vip_authmethod") != "key" && r.FormValue("bind_vip_authmethod") != "password" {
		error_msg = "绑定网卡登录认证方式值[" + r.FormValue("bind_vip_authmethod") + "]非法"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断绑定操作用户密码是否为空
	if r.FormValue("bind_vip_authmethod") == "password" && r.FormValue("bind_vip_password") == "" {
		error_msg = "绑定操作用户密码不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	row := <-row_chan

	if row.Return_code == "FAIL" {
		error_msg = "获取节点资料失败,详情：" + row.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//绑定或解绑vip,则需要做一些检查工作
	cmd := ""
	if r.FormValue("act") == "bind" {
		//绑定前需要检查ip是否占用
		cmd = "ping " + r.FormValue("vip") + " -c 3 | grep 'ttl'"
	} else {
		//解绑的需要检查ip是否已经绑定在要解绑的设备上面
		cmd = "cmdpath=`which 'ip'`;$cmdpath a |grep '" + r.FormValue("vip") + "'|grep '" + r.FormValue("vip_networkcard") + "'"
	}
	stdout, stderr := ssh_run(r.FormValue("bind_vip_authmethod"), "root", r.FormValue("bind_vip_user"), r.FormValue("bind_vip_password"), row.Host, row.Ssh_port, cmd)
	if stderr != "" {
		if r.FormValue("act") == "bind" {
			error_msg = "检查要绑定的VIP[" + r.FormValue("vip") + "]是否已经被占用时出错，详情：" + stderr
		} else {
			error_msg = "检查要解绑的VIP[" + r.FormValue("vip") + "]出错，详情：" + stderr
		}
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	if stdout != "" && r.FormValue("act") == "bind" {
		error_msg = "要绑定的VIP[" + r.FormValue("vip") + "]已经被占用,需要先从占用的机器上解绑"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	if stdout == "" && r.FormValue("act") == "unbind" {
		error_msg = "要解绑的VIP[" + r.FormValue("vip") + "]不存在,请确认绑定的网卡[" + r.FormValue("vip_networkcard") + "]是否配置正确"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//执行解绑或绑定VIP操作
	if r.FormValue("act") == "bind" {
		cmd = "cmdpath=`which 'ifconfig'`;$cmdpath '" + r.FormValue("vip_networkcard") + "' '" + r.FormValue("vip") + "'"
	} else {
		cmd = "cmdpath=`which 'ip'`;$cmdpath addr del '" + r.FormValue("vip") + "/24' dev '" + r.FormValue("vip_networkcard") + "'"
	}
	stdout, stderr = ssh_run(r.FormValue("bind_vip_authmethod"), "root", r.FormValue("bind_vip_user"), r.FormValue("bind_vip_password"), row.Host, row.Ssh_port, cmd)
	if stderr != "" {
		if r.FormValue("act") == "bind" {
			error_msg = "绑定vip出错，详情：" + stderr
		} else {
			error_msg = "解绑vip出错，详情：" + stderr
		}
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	OutputJson(w, "SUCCESS", "执行成功！", 0)
	go write_log(remote_ip, modlename, username, "Log", "执行成功，id [ "+r.FormValue("id")+" ]")
	return
}

/*
功能描述：获取某个节点的ip绑定情况并输出给客户端

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func get_ip_bind_statusHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	modlename := "get_ip_bind_statusHandler"
	remote_ip := get_remote_ip(r)
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//判断主节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = "节点id号不是合法的int类型，id号为 [ " + r.FormValue("id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取节点ip绑定情况
	ip_status_chan := make(chan Stdout_and_stderr)
	go get_node_ip_bind_status(id, ip_status_chan)
	//获取访问主节点异常执行返回ip绑定结果
	ip_status_ret := <-ip_status_chan
	if ip_status_ret.Stderr != "" {
		error_msg = "获取主节点ip绑定情况失败，详情：" + ip_status_ret.Stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//定义返回的结构体
	type Ret struct {
		Return_code       string `json:"return_code"`
		Return_msg        string `json:"return_msg"`
		Show_login_dialog int    `json:"show_login_dialog"`
		Ip_bind_status    string `json:"ip_bind_status"`
	}

	out := &Ret{"SUCCESS", "获取成功", 0, ip_status_ret.Stdout}
	b, _ := json.Marshal(out)
	w.Write(b)
}

/*
功能描述：唤醒管理接口

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func slave_wakeupHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	modlename := "slave_wakeupHandler"
	remote_ip := get_remote_ip(r)
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//判断主节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = "节点id号不是合法的int类型，id号为 [ " + r.FormValue("id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断要操作的VIP地址是否为合法的IP地址
	if r.FormValue("vip") != "" && !str_is_ip(r.FormValue("vip")) {
		error_msg = "VIP[" + r.FormValue("vip") + "]不是合法的ip地址"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	//判断设备号是否为空
	if r.FormValue("vip") != "" && r.FormValue("vip_networkcard") == "" {
		error_msg = "网卡设备号不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断bind_vip_authmethod字符值是否合法
	if r.FormValue("bind_vip_authmethod") != "key" && r.FormValue("bind_vip_authmethod") != "password" {
		error_msg = "绑定网卡登录认证方式值[" + r.FormValue("bind_vip_authmethod") + "]非法"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断绑定操作用户名是否为空
	if r.FormValue("vip") != "" && r.FormValue("bind_vip_user") == "" {
		error_msg = "绑定操作用户名不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断绑定操作用户密码是否为空
	if r.FormValue("vip") != "" && r.FormValue("bind_vip_authmethod") == "password" && r.FormValue("bind_vip_password") == "" {
		error_msg = "绑定操作用户密码不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	row := <-row_chan
	if row.Return_code == "FAIL" {
		error_msg = "获取节点资料失败,详情：" + row.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//如果绑定vip,则需要做一些检查工作
	cmd := ""
	bindvip := 1
	if r.FormValue("vip") != "" {
		//判断绑定vip和设备号是否已经在本机上存在
		cmd = "cmdpath=`which 'ip'`;$cmdpath a |grep '" + r.FormValue("vip") + "'|grep '" + r.FormValue("vip_networkcard") + "'"
		stdout, stderr := ssh_run(r.FormValue("bind_vip_authmethod"), "root", r.FormValue("bind_vip_user"), r.FormValue("bind_vip_password"), row.Host, row.Ssh_port, cmd)
		if stderr != "" {
			error_msg = "检查要绑定的VIP[" + r.FormValue("vip") + "]是否已经在本机上绑定出错，详情：" + stderr
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		//没有在本机上绑定需要判断是否已经在其它机器上已经绑定
		if stdout == "" {
			cmd = "ping " + r.FormValue("vip") + " -c 3 | grep 'ttl'"
			stdout, stderr = ssh_run(r.FormValue("bind_vip_authmethod"), "root", r.FormValue("bind_vip_user"), r.FormValue("bind_vip_password"), row.Host, row.Ssh_port, cmd)
			if stderr != "" {
				error_msg = "检查要绑定的VIP[" + r.FormValue("vip") + "]是否已经被占用时出错，详情：" + stderr
				OutputJson(w, "FAIL", error_msg, 0)
				go write_log(remote_ip, modlename, username, "Error", error_msg)
				return
			}
			if stdout != "" {
				error_msg = "要绑定的VIP[" + r.FormValue("vip") + "]已经被占用,需要先从占用的机器上解绑"
				OutputJson(w, "FAIL", error_msg, 0)
				go write_log(remote_ip, modlename, username, "Error", error_msg)
				return
			}
		} else {
			//已经在本机上绑定了vip,后面不需要再绑定vip
			bindvip = 0
		}
	}

	var stderr string

	//获取节点的状态
	go getnode_type_and_status(row_chan, row)
	row = <-row_chan
	if row.Service_type != "备节点" {
		error_msg = "非备节点,无需要唤醒node_id号 [ " + r.FormValue("id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	if row.Service_status == "运行中" {
		cmd = row.Pg_bin + "pg_ctl promote -D " + row.Pg_data + " > " + row.Pg_data + username + "_slave_wakeup.log"
	} else {
		cmd = "rm " + row.Pg_data + "recovery.done -rf;mv " + row.Pg_data + "recovery.conf " + row.Pg_data + "recovery.done"
		cmd = row.Pg_bin + "pg_ctl start -D " + row.Pg_data + " > " + row.Pg_data + username + "_slave_wakeup.log"
	}
	_, stderr = ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
	if stderr != "" {
		error_msg = "备机唤醒出错,详情:" + stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//执行绑定VIP操作
	if r.FormValue("vip") != "" && bindvip == 1 {
		cmd = "cmdpath=`which 'ifconfig'`;$cmdpath '" + r.FormValue("vip_networkcard") + "' '" + r.FormValue("vip") + "'"
		_, stderr = ssh_run(r.FormValue("bind_vip_authmethod"), "root", r.FormValue("bind_vip_user"), r.FormValue("bind_vip_password"), row.Host, row.Ssh_port, cmd)
		if stderr != "" {
			error_msg = "备机唤醒成功,但绑定vip出错，详情：" + stderr
			OutputJson(w, "SUCCESS", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//检查节点是否为同步复制模式并且没备机连接上来
	var config pgx.ConnConfig
	config.Host = row.Host
	config.User = row.Pg_user
	config.Password = row.Pg_password
	config.Database = row.Pg_database
	config.Port = row.Pg_port
	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(config)
	if err != nil {
		error_msg = "连接db失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()
	sql := "select current_setting('synchronous_standby_names') as sync,coalesce((select sync_state from pg_stat_replication where sync_state='sync' limit 1),'') as sync_state"
	rows, err := conn.Query(sql)
	if err != nil {
		error_msg = "备机唤醒成功,但连接数据库失败，详情：" + err.Error()
		OutputJson(w, "SUCCESS", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	if rows.Next() {
		var sync string
		var sync_state string
		err = rows.Scan(&sync, &sync_state)
		if err != nil {
			error_msg = "备机唤醒成功,但查询其流复制模式失败，详情：" + err.Error()
			OutputJson(w, "SUCCESS", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		//采用同步模式并且没有同步备节点存在,这里需要变成异步模式,否则无法做vacuum analyze
		if sync != "" && sync_state == "" {
			parameter_file_name := row.Pg_data + "postgresql.conf"
			cmd = "cat " + parameter_file_name
			stdout, stderr := ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
			if stderr != "" {
				error_msg = "获取配置文件内容出错,详情：" + stderr
				OutputJson(w, "FAIL", error_msg, 0)
				go write_log(remote_ip, modlename, username, "Error", error_msg)
				return
			}
			stdout = strings.Replace(stdout, "synchronous_standby_names", "#synchronous_standby_names", 1)
			cmd = "cp " + parameter_file_name + " " + parameter_file_name + ".slave_wakeup.bak" + ";echo \"" + stdout + "\" > " + parameter_file_name
			logfile := row.Pg_data + "slave_wakeup_" + username + "_restart.txt"
			cmd = cmd + ";" + row.Pg_bin + "pg_ctl restart -D " + row.Pg_data + " -m fast >" + logfile
			_, stderr = ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
			if stderr != "" {
				error_msg = "修改节点流复制模式后重启出错,详情：" + stderr
				OutputJson(w, "FAIL", error_msg, 0)
				go write_log(remote_ip, modlename, username, "Error", error_msg)
				return
			}
		}
	}

	//判断是否需要做全库vacuum
	if r.FormValue("vacuum_check") == "1" {
		go vacuumdb(id, remote_ip, username)
	}

	OutputJson(w, "SUCCESS", "执行成功！", 0)
	go write_log(remote_ip, modlename, username, "Log", "执行成功，id [ "+r.FormValue("id")+" ]")
	//执行全库vacuum
	return
}

/*
功能描述：主备切换

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func promoteHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	modlename := "promoteHandler"
	remote_ip := get_remote_ip(r)
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//检查master_id是否合法
	master_id, err := strconv.Atoi(r.FormValue("master_id"))
	if err != nil {
		error_msg = "非法的master_id号 [ " + r.FormValue("master_id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//检查slave_id是否合法
	slave_id, err := strconv.Atoi(r.FormValue("slave_id"))
	if err != nil {
		error_msg = "非法的slave_id号 [ " + r.FormValue("slave_id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断主备切换前，要解绑的主备vip是否相同
	if r.FormValue("master_unbind_vip") != "" && r.FormValue("master_unbind_vip") == r.FormValue("slave_unbind_vip") {
		error_msg = "主备切换前，主备节点要解绑的vip不能相同"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断主备切换后，要绑定的主备vip是否相同
	if r.FormValue("master_bind_vip") != "" && r.FormValue("master_bind_vip") == r.FormValue("slave_bind_vip") {
		error_msg = "主备切换后，主备节点要绑定的vip不能相同"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("master_unbind_vip") != "" && r.FormValue("master_unbind_vip_networkcard") == "" {
		error_msg = "主备切换前，主节点要解绑的网卡设备号不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("master_bind_vip") != "" && r.FormValue("master_bind_vip_networkcard") == "" {
		error_msg = "主备切换后，备节点要绑定的网卡设备号不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("slave_unbind_vip") != "" && r.FormValue("slave_unbind_vip_networkcard") == "" {
		error_msg = "主备切换前，备节点要解绑的网卡设备号不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("slave_bind_vip") != "" && r.FormValue("slave_bind_vip_networkcard") == "" {
		error_msg = "主备切换后，主节点要绑定的网卡设备号不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//如果主节点需要绑定或解绑vip，则操作用户不能这空，如果认证方式选择是密码认证，则密码也不能为空
	if r.FormValue("master_unbind_vip") != "" || r.FormValue("master_bind_vip") != "" {
		if r.FormValue("master_bind_user") == "" {
			error_msg = "操作主节点的“绑定或解绑操作用户”不能为空"
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		if r.FormValue("master_bind_password") == "" && r.FormValue("master_bind_vip_authmethod") == "password" {
			error_msg = "操作主节点的“绑定或解绑操作用户密码”不能为空"
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//如果备节点需要绑定或解绑vip，则操作用户不能这空，如果认证方式选择是密码认证，则密码也不能为空
	if r.FormValue("slave_unbind_vip") != "" || r.FormValue("slave_bind_vip") != "" {
		if r.FormValue("slave_bind_user") == "" {
			error_msg = "操作备节点的“绑定或解绑操作用户”不能为空"
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		if r.FormValue("slave_bind_password") == "" && r.FormValue("slave_bind_vip_authmethod") == "password" {
			error_msg = "操作备节点的“绑定或解绑操作用户密码”不能为空"
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//获取master节点资料
	row_chan := make(chan Row)
	go get_node_row(master_id, row_chan)
	master_row := <-row_chan
	if master_row.Return_code == "FAIL" {
		error_msg = "获取master节点资料失败,详情：" + master_row.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//获取slave节点资料
	go get_node_row(slave_id, row_chan)
	slave_row := <-row_chan
	if master_row.Return_code == "FAIL" {
		error_msg = "获取master节点资料失败,详情：" + slave_row.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步检查两个节点是否为主备关系
	master_slave_relation_check_chan := make(chan string)
	go master_slave_relation_check(master_row, slave_row, master_slave_relation_check_chan)

	//如果主节点需要解绑vip，则需要做一些检查工作
	master_unbind_vip_chan := make(chan Stdout_and_stderr)
	if r.FormValue("master_unbind_vip") != "" {
		//判断解绑vip是否存在
		cmd := "cmdpath=`which 'ip'`;$cmdpath a |grep '" + r.FormValue("master_unbind_vip") + "'|grep '" + r.FormValue("master_unbind_vip_networkcard") + "'"
		go ssh_run_chan(r.FormValue("master_bind_vip_authmethod"), "root", r.FormValue("master_bind_user"), r.FormValue("master_bind_password"), master_row.Host, master_row.Ssh_port, cmd, master_unbind_vip_chan)
	}

	//如果备节点需要解绑vip，则需要做一些检查工作
	slave_unbind_vip_chan := make(chan Stdout_and_stderr)
	if r.FormValue("slave_unbind_vip") != "" {
		//判断解绑vip是否存在
		cmd := "cmdpath=`which 'ip'`;$cmdpath a |grep '" + r.FormValue("slave_unbind_vip") + "'|grep '" + r.FormValue("slave_unbind_vip_networkcard") + "'"
		go ssh_run_chan(r.FormValue("slave_bind_vip_authmethod"), "root", r.FormValue("slave_bind_user"), r.FormValue("slave_bind_password"), slave_row.Host, slave_row.Ssh_port, cmd, slave_unbind_vip_chan)
	}

	//如果主节点需要绑定vip,并且要绑定的vip不是备节点要解绑的Vip，则需要做一些检查工作
	master_bind_vip_chan := make(chan Stdout_and_stderr)
	if r.FormValue("master_bind_vip") != "" && r.FormValue("master_bind_vip") != r.FormValue("slave_unbind_vip") {
		cmd := "ping " + r.FormValue("master_bind_vip") + " -c 3 | grep 'ttl'"
		go ssh_run_chan(r.FormValue("master_bind_vip_authmethod"), "root", r.FormValue("master_bind_user"), r.FormValue("master_bind_password"), master_row.Host, master_row.Ssh_port, cmd, master_bind_vip_chan)
	}

	//如果备节点需要绑定vip,并且要绑定的vip不是主节点要解绑的Vip，则需要做一些检查工作
	slave_bind_vip_chan := make(chan Stdout_and_stderr)
	if r.FormValue("slave_bind_vip") != "" && r.FormValue("slave_bind_vip") != r.FormValue("master_unbind_vip") {
		cmd := "ping " + r.FormValue("slave_bind_vip") + " -c 3 | grep 'ttl'"
		go ssh_run_chan(r.FormValue("slave_bind_vip_authmethod"), "root", r.FormValue("slave_bind_user"), r.FormValue("slave_bind_password"), slave_row.Host, slave_row.Ssh_port, cmd, slave_bind_vip_chan)
	}

	//如果主节点需要解绑vip，前面则需要做一些检查工作,现在获取异步执行结果
	if r.FormValue("master_unbind_vip") != "" {
		master_unbind_vip_ret := <-master_unbind_vip_chan
		if master_unbind_vip_ret.Stderr != "" {
			error_msg = "主节点切为备节点，检查要解绑的VIP[" + r.FormValue("master_unbind_vip") + "]出错，详情：" + master_unbind_vip_ret.Stderr
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		if master_unbind_vip_ret.Stdout == "" {
			error_msg = "主节点切为备节点，要解绑的VIP[" + r.FormValue("master_unbind_vip") + "]不存在,请确认绑定的网卡[" + r.FormValue("master_unbind_vip_networkcard") + "]是否配置正确"
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//如果备节点需要解绑vip，前面则需要做一些检查工作,现在获取异步执行结果
	if r.FormValue("slave_unbind_vip") != "" {
		slave_unbind_vip_ret := <-slave_unbind_vip_chan
		if slave_unbind_vip_ret.Stderr != "" {
			error_msg = "备节点切为主节点，检查要解绑的VIP[" + r.FormValue("slave_unbind_vip") + "]出错，详情：" + slave_unbind_vip_ret.Stderr
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		if slave_unbind_vip_ret.Stdout == "" {
			error_msg = "备节点切为主节点，要解绑的VIP[" + r.FormValue("slave_unbind_vip") + "]不存在,请确认绑定的网卡[" + r.FormValue("slave_unbind_vip_networkcard") + "]是否配置正确"
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//如果主节点需要绑定vip,并且要绑定的vip不是备节点要解绑的Vip，前面则需要做一些检查工作,现在获取异步执行结果
	if r.FormValue("master_bind_vip") != "" && r.FormValue("master_bind_vip") != r.FormValue("slave_unbind_vip") {
		master_bind_vip_ret := <-master_bind_vip_chan
		if master_bind_vip_ret.Stderr != "" {
			error_msg = "主节点切为备节点,检查要绑定的VIP[" + r.FormValue("master_bind_vip") + "]是否已经被占用时出错，详情：" + master_bind_vip_ret.Stderr
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		if master_bind_vip_ret.Stdout != "" {
			error_msg = "主节点切为备节点后要绑定的VIP[" + r.FormValue("master_bind_vip") + "]已经被占用,需要先从占用的机器上解绑"
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//如果备节点需要绑定vip,并且要绑定的vip不是主节点要解绑的Vip，前面则需要做一些检查工作,现在获取异步执行结果
	if r.FormValue("slave_bind_vip") != "" && r.FormValue("slave_bind_vip") != r.FormValue("master_unbind_vip") {
		slave_bind_vip_ret := <-slave_bind_vip_chan
		if slave_bind_vip_ret.Stderr != "" {
			error_msg = "备节点切为主节点，检查要绑定的VIP[" + r.FormValue("slave_bind_vip") + "]是否已经被占用时出错，详情：" + slave_bind_vip_ret.Stderr
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		if slave_bind_vip_ret.Stdout != "" {
			error_msg = "备节点切为主节点后要绑定的VIP[" + r.FormValue("slave_bind_vip") + "]已经被占用,需要先从占用的机器上解绑"
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//异步获取--检查两个节点是否为主备关系结果
	ret := <-master_slave_relation_check_chan
	if ret != "" {
		error_msg = "检查两个节点是否为主备关系出错，详情：" + ret
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//OutputJson(w,"FAIL","程序测试中！",0)
	//return

	//切换前主节点解绑vip
	if r.FormValue("master_unbind_vip") != "" {
		//异步执行解绑vip工作
		cmd := "cmdpath=`which 'ip'`;$cmdpath addr del '" + r.FormValue("master_unbind_vip") + "/24' dev '" + r.FormValue("master_unbind_vip_networkcard") + "'"
		go ssh_run_chan(r.FormValue("master_bind_vip_authmethod"), "root", r.FormValue("master_bind_user"), r.FormValue("master_bind_password"), master_row.Host, master_row.Ssh_port, cmd, master_unbind_vip_chan)
	}

	//切换前备节点解绑vip
	if r.FormValue("slave_unbind_vip") != "" {
		//异步执行解绑vip工作
		cmd := "cmdpath=`which 'ip'`;$cmdpath addr del '" + r.FormValue("slave_unbind_vip") + "/24' dev '" + r.FormValue("slave_unbind_vip_networkcard") + "'"
		go ssh_run_chan(r.FormValue("slave_bind_vip_authmethod"), "root", r.FormValue("slave_bind_user"), r.FormValue("slave_bind_password"), slave_row.Host, slave_row.Ssh_port, cmd, slave_unbind_vip_chan)
	}

	//如果切换前主节点解绑vip,前面则需要做异步做处理工作,现在获取异步执行结果
	if r.FormValue("master_unbind_vip") != "" {
		master_unbind_vip_ret := <-master_unbind_vip_chan
		if master_unbind_vip_ret.Stderr != "" {
			error_msg = "主节点切为备节点，切换前执行解绑vip出错，详情：" + master_unbind_vip_ret.Stderr
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//如果切换前备节点解绑vip,前面则需要做异步做处理工作,现在获取异步执行结果
	if r.FormValue("slave_unbind_vip") != "" {
		slave_unbind_vip_ret := <-slave_unbind_vip_chan
		if slave_unbind_vip_ret.Stderr != "" {
			error_msg = "备节点切为主节点，切换前执行解绑vip出错，详情：" + slave_unbind_vip_ret.Stderr
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//下面开始执行主备切换
	//关闭主节点服务
	cmd := master_row.Pg_bin + "pg_ctl stop -D " + master_row.Pg_data + " -m fast" + " > " + master_row.Pg_data + username + "_promote_stop_logfile.txt;"
	cmd = cmd + "cat " + master_row.Pg_data + username + "_promote_stop_logfile.txt"
	_, stderr := ssh_run(master_row.Ssh_authmethod, "postgres", master_row.Ssh_user, master_row.Ssh_password, master_row.Host, master_row.Ssh_port, cmd)

	if stderr != "" {
		error_msg = "关闭主节点服务出错，详情：" + stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//promote备节点
	cmd = "rm " + slave_row.Pg_data + "recovery.done -f;"
	cmd = cmd + slave_row.Pg_bin + "pg_ctl promote -D " + slave_row.Pg_data + " > " + slave_row.Pg_data + username + "_promote_logfile.txt ;"
	cmd = cmd + "cat " + slave_row.Pg_data + username + "_promote_logfile.txt"
	_, stderr = ssh_run(slave_row.Ssh_authmethod, "postgres", slave_row.Ssh_user, slave_row.Ssh_password, slave_row.Host, slave_row.Ssh_port, cmd)

	if stderr != "" {
		error_msg = "promote备节点出错，详情：" + stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//把主节点变成备节点
	cmd = "rm " + master_row.Pg_data + "recovery.conf -f;"
	cmd = cmd + "echo \"" + r.FormValue("recovery_conf") + "\">" + master_row.Pg_data + "/recovery.conf;"
	cmd = cmd + master_row.Pg_bin + "pg_ctl start -D " + master_row.Pg_data + " > " + master_row.Pg_data + username + "_promote_start_logfile.txt ;"
	cmd = cmd + "cat " + master_row.Pg_data + username + "_promote_start_logfile.txt"
	_, stderr = ssh_run(master_row.Ssh_authmethod, "postgres", master_row.Ssh_user, master_row.Ssh_password, master_row.Host, master_row.Ssh_port, cmd)

	if stderr != "" {
		error_msg = "把主节点变为备节点时出错，详情：" + stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//主备切换切换工作结束

	//切换后检查两个节点是否为主备关系
	for i := 0; i < 10; i++ {
		go master_slave_relation_check(slave_row, master_row, master_slave_relation_check_chan)
		ret := <-master_slave_relation_check_chan
		if ret == "" {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if ret != "" {
		error_msg = "切换后验证失败，详情：" + ret
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//切换后原来的主节点（现在变成备节点了）需要绑定vip
	if r.FormValue("master_bind_vip") != "" {
		//异步绑定vip
		cmd := "cmdpath=`which 'ifconfig'`;$cmdpath '" + r.FormValue("master_bind_vip_networkcard") + "' '" + r.FormValue("master_bind_vip") + "'"
		go ssh_run_chan(r.FormValue("master_bind_vip_authmethod"), "root", r.FormValue("master_bind_user"), r.FormValue("master_bind_password"), master_row.Host, master_row.Ssh_port, cmd, master_bind_vip_chan)
	}

	//切换后原来的备节点（现在变成主节点了）需要绑定vip
	if r.FormValue("slave_bind_vip") != "" {
		//异步绑定vip
		cmd := "cmdpath=`which 'ifconfig'`;$cmdpath '" + r.FormValue("slave_bind_vip_networkcard") + "' '" + r.FormValue("slave_bind_vip") + "'"
		go ssh_run_chan(r.FormValue("slave_bind_vip_authmethod"), "root", r.FormValue("slave_bind_user"), r.FormValue("slave_bind_password"), slave_row.Host, slave_row.Ssh_port, cmd, slave_bind_vip_chan)
	}

	//切换后原来的主节点（现在变成备节点了）需要绑定vip,前面则做了异步绑定处理,现在获取异步执行结果
	if r.FormValue("master_bind_vip") != "" {
		master_bind_vip_ret := <-master_bind_vip_chan
		if master_bind_vip_ret.Stderr != "" {
			error_msg = "切换成功，但主节点切为备节点后绑定vip出错，详情：" + master_bind_vip_ret.Stderr
			OutputJson(w, "SUCCESS", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//切换后原来的备节点（现在变成主节点了）需要绑定vip,前面则做了异步绑定处理,现在获取异步执行结果
	if r.FormValue("slave_bind_vip") != "" {
		slave_bind_vip_ret := <-slave_bind_vip_chan
		if slave_bind_vip_ret.Stderr != "" {
			error_msg = "切换成功，但备节点切为主节点后绑定vip出错，详情：" + slave_bind_vip_ret.Stderr
			OutputJson(w, "SUCCESS", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	OutputJson(w, "SUCCESS", "切换成功！", 0)
	go write_log(remote_ip, modlename, username, "Log", "切换成功，master_id [ "+r.FormValue("master_id")+" ],slave_id [ "+r.FormValue("slave_id")+" ]")
	return
}

/*
功能描述：检查两个节点是否为主备关系

参数说明：
master_row -- Row结构指针
slave_row  -- Row结构指针

返回值说明：
return_msg -- 执行出错返回信息，如果检查两个节点为主备关系则返回空字符串""
*/

func master_slave_relation_check(master_row Row, slave_row Row, s chan string) {
	//通过pg_controldata先确认两个节点的状态是否正确
	//异步检查主节点
	cmd := master_row.Pg_bin + "pg_controldata " + master_row.Pg_data
	master_out_chan := make(chan Stdout_and_stderr)
	go ssh_run_chan(master_row.Ssh_authmethod, "postgres", master_row.Ssh_user, master_row.Ssh_password, master_row.Host, master_row.Ssh_port, cmd, master_out_chan)

	//异步检查备节点
	cmd = slave_row.Pg_bin + "pg_controldata " + slave_row.Pg_data + ";cat " + slave_row.Pg_data + "recovery.conf"
	slave_out_chan := make(chan Stdout_and_stderr)
	go ssh_run_chan(slave_row.Ssh_authmethod, "postgres", slave_row.Ssh_user, slave_row.Ssh_password, slave_row.Host, slave_row.Ssh_port, cmd, slave_out_chan)

	//获取异步检查主节点返回的信息
	master_ret := <-master_out_chan
	if master_ret.Stderr != "" {
		s <- "pg_controldata获取主节点信息出错，详情：" + master_ret.Stderr
		return
	}
	if !strings.Contains(master_ret.Stdout, "in production") {
		s <- "pg_controldata检查到主节点处于非运行状态，不可以切换"
		return
	}

	//获取异步检查备节点返回的信息
	slave_ret := <-slave_out_chan
	if slave_ret.Stderr != "" {
		s <- "pg_controldata获取备节点信息出错，详情：" + master_ret.Stderr
		return
	}
	if !strings.Contains(slave_ret.Stdout, "in archive recovery") {
		s <- "pg_controldata检查到备节点处于非运行状态，不可以切换"
		return
	}
	if !strings.Contains(slave_ret.Stdout, "host="+master_row.Host+" port="+fmt.Sprintf("%d", master_row.Pg_port)) {
		s <- "pg_controldata检查到要切换的两个节点非主备关系，不可以切换"
		return
	}

	//通过连接数据库确认两个节点的状态是否正确

	//连接master_db
	var master_config pgx.ConnConfig
	master_config.Host = master_row.Host
	master_config.User = master_row.Pg_user
	master_config.Password = master_row.Pg_password
	master_config.Database = master_row.Pg_database
	master_config.Port = master_row.Pg_port

	var master_conn *pgx.Conn
	master_conn, err := pgx.Connect(master_config)
	if err != nil {
		s <- "连接主节点服务出错，详情：" + err.Error()
		return
	}
	defer master_conn.Close()
	sql := "select CASE WHEN current_setting('wal_level') in ('minimal','archive') THEN '普通节点' WHEN pg_is_in_recovery() THEN '备节点' ELSE '主节点' END AS service_type from pg_stat_replication where client_addr='" + slave_row.Host + "' and state='streaming'"
	rows, err := master_conn.Query(sql)
	if err != nil {
		s <- "查询获取主节点类型出错，详情：" + err.Error()
		return
	}
	if rows.Next() {
		var master_service_type string
		err = rows.Scan(&master_service_type)
		if err != nil {
			s <- "查询获取主节点类型出错，详情：" + err.Error()
			return
		}
		if master_service_type != "主节点" {
			s <- "查询获取主节点类型为非主节点，不可以切换"
			return
		}
	} else {
		s <- "查询主节点检查到要切换的两个节点非主备关系，不可以切换"
		return
	}
	rows.Close()

	//连接slave_db
	var slave_config pgx.ConnConfig
	slave_config.Host = slave_row.Host
	slave_config.User = slave_row.Pg_user
	slave_config.Password = slave_row.Pg_password
	slave_config.Database = slave_row.Pg_database
	slave_config.Port = slave_row.Pg_port

	var slave_conn *pgx.Conn
	slave_conn, err = pgx.Connect(slave_config)
	if err != nil {
		s <- "连接备节点服务出错，详情：" + err.Error()
		return
	}
	defer slave_conn.Close()
	sql = "select CASE WHEN current_setting('wal_level') in ('minimal','archive') THEN '普通节点' WHEN pg_is_in_recovery() THEN '备节点' ELSE '主节点' END AS service_type,pg_read_file('recovery.conf') AS recovery "
	rows, err = slave_conn.Query(sql)
	if err != nil {
		s <- "查询获取备节点类型出错，详情：" + err.Error()
		return
	}
	defer rows.Close()
	if rows.Next() {
		var slave_recovery string
		var slave_service_type string
		err = rows.Scan(&slave_service_type, &slave_recovery)
		if err != nil {
			s <- "查询获取备节点类型出错，详情：" + err.Error()
			return
		}
		if slave_service_type != "备节点" {
			s <- "查询获取备节点类型为非备节点，不可以切换"
			return
		}
		if !strings.Contains(slave_recovery, "host="+master_row.Host+" port="+fmt.Sprintf("%d", master_row.Pg_port)) {
			s <- "备节点上查询检查到要切换的两个节点非主备关系，不可以切换"
			return
		}
	} else {
		s <- "备节点查询要切换的两个节点之间的关系出错"
		return
	}
	s <- ""
}

/*
功能描述：主备切换窗口打开时获取主备节点的ip绑定情况

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func promote_get_ip_bind_statusHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	modlename := "promote_get_ip_bind_statusHandler"
	remote_ip := get_remote_ip(r)
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	//判断主节点master_id合法性
	master_id, err := strconv.Atoi(r.FormValue("master_id"))
	if err != nil {
		error_msg = "主节点id号不是合法的int类型，id号为 [ " + r.FormValue("master_id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断备节点slave_id合法性
	slave_id, err := strconv.Atoi(r.FormValue("slave_id"))
	if err != nil {
		error_msg = "备节点id号不是合法的int类型，id号为 [ " + r.FormValue("slave_id") + " ]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取主节点ip绑定情况
	master_ip_status_chan := make(chan Stdout_and_stderr)
	go get_node_ip_bind_status(master_id, master_ip_status_chan)

	//异步获取备节点ip绑定情况
	slave_ip_status_chan := make(chan Stdout_and_stderr)
	go get_node_ip_bind_status(slave_id, slave_ip_status_chan)

	//获取访问主节点异常执行返回ip绑定结果
	master_ret := <-master_ip_status_chan
	if master_ret.Stderr != "" {
		error_msg = "获取主节点ip绑定情况失败，详情：" + master_ret.Stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//获取访问主节点异常执行返回ip绑定结果
	slave_ret := <-slave_ip_status_chan
	if slave_ret.Stderr != "" {
		error_msg = "获取备节点ip绑定情况失败，详情：" + slave_ret.Stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//定义返回的结构体
	type Ret struct {
		Return_code       string `json:"return_code"`
		Return_msg        string `json:"return_msg"`
		Show_login_dialog int    `json:"show_login_dialog"`
		Master_ip_status  string `json:"master_ip_status"`
		Slave_ip_status   string `json:"slave_ip_status"`
	}

	out := &Ret{"SUCCESS", "获取成功", 0, master_ret.Stdout, slave_ret.Stdout}
	b, _ := json.Marshal(out)
	w.Write(b)
}

/*
功能描述：巡检报告生成接口

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_makeHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_makeHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "巡检报告生成－－节点ID号为[" + r.FormValue("id") + "]－－"

	//判断节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = error_msg + "节点id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	//判断表行数统计进程数合法性
	count_recordnum_processes, err := strconv.Atoi(r.FormValue("count_recordnum_processes"))
	if err != nil {
		error_msg = error_msg + "表行数统计进程数不是合法的数字[" + r.FormValue("count_recordnum_processes") + "]"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断report_name是否为空
	if r.FormValue("report_name") == "" {
		error_msg = error_msg + "巡检报告名称不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	row := <-row_chan
	if row.Return_code == "FAIL" {
		error_msg = error_msg + "获取节点资料失败－－详情：" + row.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//重新获取节点的状态
	go getnode_type_and_status(row_chan, row)
	row = <-row_chan

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		error_msg = error_msg + "连接数据库失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	var sql string
	var inspection_report_id int
	//不统计表记录数
	var count_finish string
	if count_recordnum_processes == 0 {
		count_finish = "是"
	} else {
		count_finish = "否"
	}

	sql = `
    INSERT INTO inspection_report
    (
        nodeid,report_name, 
		createtime,username,
		count_finish
    ) 
    VALUES
    (   
        $1,$2,
	    now(),$3,
		$4
    ) returning id    
    `
	rows, err := conn.Query(sql, r.FormValue("id"), r.FormValue("report_name"), username, count_finish)

	if err != nil {
		error_msg = error_msg + "插入主表记录失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	} else {
		if rows.Next() {
			err = rows.Scan(&inspection_report_id)
			if err != nil {
				error_msg = error_msg + "提取主表数据失败，详情：" + err.Error()
				OutputJson(w, "FAIL", error_msg, 0)
				go write_log(remote_ip, modlename, username, "Error", error_msg)
				return
			}
		} else {
			error_msg = error_msg + "无法获取新增报告的ID号"
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
	}

	//异步数据库统计生成
	DatabaseData_chan := make(chan DatabaseData)
	go inspection_report_database_make(inspection_report_id, r.FormValue("database"), r.FormValue("count_system_obj"), row, DatabaseData_chan)
	databases := <-DatabaseData_chan
	if databases.Err != "" {
		error_msg = error_msg + databases.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)

		//数据出错异步删除巡检报告
		delete_chan := make(chan Stdout_and_stderr)
		go inspection_report_delete(inspection_report_id, delete_chan)
		return
	}

	chan_num := 2 + databases.Total*3
	end := make(chan Stdout_and_stderr, chan_num)
	//异步生成数据表、索引和外部表
	for i := 0; i < databases.Total; i++ {
		row.Pg_database = databases.Rows[i]
		go inspection_report_table_make(inspection_report_id, r.FormValue("count_system_obj"), row, end)
		go inspection_report_index_make(inspection_report_id, r.FormValue("count_system_obj"), row, end)
		go inspection_report_foreign_table_make(inspection_report_id, row, end)
	}
	//异步生成用户角色
	go inspection_report_role_make(inspection_report_id, row, end)
	//异步表空间统计生成
	go inspection_report_tablespace_make(inspection_report_id, row, end)

	//获取角色统计生成结果
	var out Stdout_and_stderr
	out.Stdout = ""
	out.Stderr = ""
	for i := 0; i < chan_num; i++ {
		t := <-end
		if t.Stderr != "" {
			out = t
		}
	}
	if out.Stderr != "" {
		//数据出错异步删除巡检报告
		error_msg = error_msg + out.Stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)

		delete_chan := make(chan Stdout_and_stderr)
		go inspection_report_delete(inspection_report_id, delete_chan)
		return
	}
	//状态统计
	go inspection_report_state_make(inspection_report_id, row, end)
	t := <-end
	if t.Stderr != "" {
		error_msg = error_msg + t.Stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)

		//数据出错异步删除巡检报告
		delete_chan := make(chan Stdout_and_stderr)
		go inspection_report_delete(inspection_report_id, delete_chan)
		return
	}

	//表空间其它字段值异步更新
	go inspection_report_tablespace_update(inspection_report_id)
	//角色其它字段值异步更新
	go inspection_report_role_update(inspection_report_id)
	//数据库其它字段值异步更新
	go inspection_report_database_update(inspection_report_id)
	//数据表行数异步统计
	noderow := Table_rownum_update_row{row.Host, row.Pg_port, "", row.Pg_user, row.Pg_password, "", ""}
	go inspection_report_table_rownum_update(inspection_report_id, count_recordnum_processes, noderow)

	go write_log(remote_ip, modlename, username, "Log", error_msg+"报告的ID号为："+fmt.Sprintf("%d", inspection_report_id))
	OutputJson(w, "SUCCESS", "创建巡检报告成功", 0)
}

/*
功能描述：巡检报告－－获取巡检报告列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_listHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	error_msg = "巡检报告－－获取巡检报告列表－－节点ID号[" + r.FormValue("id") + "]－－"

	//巡检报告列表返回记录结构
	type Rec struct {
		Id           int    `json:"id"`
		Report_name  string `json:"report_name"`
		Createtime   string `json:"createtime"`
		Count_finish string `json:"count_finish"`
		Username     string `json:"username"`
	}
	type RecData struct {
		Total int   `json:"total"`
		Rows  []Rec `json:"rows"`
	}

	var data RecData = RecData{}
	data.Rows = make([]Rec, 0)
	data.Total = 0
	var rec Rec

	var sql string

	//判断节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = error_msg + "节点ID号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		error_msg = error_msg + "连接数据库失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql = `
    SELECT
		id,report_name,
		createtime::timestamp(0)::text,
		count_finish,
		username
	FROM 
		inspection_report
	WHERE
		nodeid=$1
		
	` + sql_sort(r)

	rows, err := conn.Query(sql, id)
	if err != nil {
		error_msg = error_msg + "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&rec.Id, &rec.Report_name, &rec.Createtime, &rec.Count_finish, &rec.Username)
		if err != nil {
			error_msg = error_msg + "提取数据失败，详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		data.Rows = append(data.Rows, rec)
		data.Total = data.Total + 1
	}

	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：巡检报告－－状态统计

参数说明：
inspection_report_id  -- 巡检报表－系统编号
row －－ 节点资料

返回值说明：
s -- 通道返回一个Stdout_and_stderr结构体
*/

//定义表空间记录struct
type Inspection_report_state struct {
	Id      int    `json:"id"`
	Subject string `json:"subject"`
	Val     string `json:"val"`
}

//定义列表返回的struct
type Inspection_report_stateData struct {
	Total int                       `json:"total"`
	Rows  []Inspection_report_state `json:"rows"`
	Err   string                    `json:"err"`
}

func inspection_report_state_make(inspection_report_id int, row Row, s chan Stdout_and_stderr) {
	var err error
	var error_msg string
	//定义返回的struct
	var out Stdout_and_stderr
	var sql string

	out.Stdout = ""
	out.Stderr = ""
	error_msg = "状态统计－－"

	//连接pgcluster数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		out.Stderr = error_msg + "连接pgcluster数据库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer conn.Close()

	sql = `
	INSERT INTO inspection_report_state
	(
		inspection_report_id,
		subject,
		val
	)
	SELECT
		` + fmt.Sprintf("%d", inspection_report_id) + ` AS inspection_report_id,
		t.*
	FROM (
			SELECT
				'主机IP' AS subject,
				'` + sql_data_encode(row.Host) + `' AS val
			UNION ALL
			SELECT
				'服务管理员' AS subject,
				'` + sql_data_encode(row.Ssh_user) + `' AS val
			UNION ALL
			SELECT
				'服务器端程序所在目录' AS subject,
				'` + sql_data_encode(row.Pg_bin) + `' AS val
			UNION ALL
			SELECT
				'data目录路径' AS subject,
				'` + sql_data_encode(row.Pg_data) + `' AS val
			UNION ALL
			SELECT
				'访问日志目录路径' AS subject,
				'` + sql_data_encode(row.Pg_log) + `' AS val
			UNION ALL
			SELECT
				'服务端口号' AS subject,
				'` + sql_data_encode(fmt.Sprintf("%d", row.Pg_port)) + `' AS val
			UNION ALL
			SELECT
				'版本号' AS subject,
				'` + sql_data_encode(row.Pg_version) + `' AS val
			UNION ALL
			SELECT
				'节点类号' AS subject,
				'` + sql_data_encode(row.Service_type) + `' AS val
			UNION ALL
			SELECT 				
				'timezone配置' AS subject,
				current_setting('timezone') AS val
			UNION ALL
			SELECT 				
				'shared_buffers配置' AS subject,
				current_setting('shared_buffers') AS val
			UNION ALL
			SELECT 				
				'autovacuum配置' AS subject,
				current_setting('autovacuum') AS val
			UNION ALL
			SELECT 				
				'log_destination配置' AS subject,
				current_setting('log_destination') AS val
			UNION ALL
			SELECT 				
				'logging_collector配置' AS subject,
				current_setting('logging_collector') AS val
			UNION ALL
			SELECT 				
				'log_timezone配置' AS subject,
				current_setting('log_timezone') AS val
			UNION ALL
			SELECT
				'占用空间' AS subject,
				COALESCE(pg_catalog.pg_size_pretty(sum(spcsize))::TEXT,'0') AS val
			FROM
				inspection_report_tablespace
			WHERE
				inspection_report_tablespace.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `
			UNION ALL
			SELECT
				'表空间数' AS subject,
				COUNT(1)::TEXT AS val
			FROM
				inspection_report_tablespace
			WHERE
				inspection_report_tablespace.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `
			UNION ALL
			SELECT
				'角色数' AS subject,
				COUNT(1)::TEXT AS val
			FROM
				inspection_report_role
			WHERE
				inspection_report_role.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `
			UNION ALL
			SELECT
				'数据库数' AS subject,
				COUNT(1)::TEXT AS val
			FROM
				inspection_report_database
			WHERE
				inspection_report_database.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `
			UNION ALL
			SELECT
				'数据表数' AS subject,
				COUNT(1)::TEXT AS val
			FROM
				inspection_report_table
			WHERE
				inspection_report_table.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `
			UNION ALL
			SELECT
				'外部表数' AS subject,
				COUNT(1)::TEXT AS val
			FROM
				inspection_report_foreign_table
			WHERE
				inspection_report_foreign_table.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `
			UNION ALL
			SELECT
				'索引数' AS subject,
				COUNT(1)::TEXT AS val
			FROM
				inspection_report_index
			WHERE
				inspection_report_index.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `
		) AS t
	`

	_, err = conn.Exec(sql)

	if err != nil {
		out.Stderr = error_msg + "插入数据失败－－详情：" + err.Error()
		s <- out
		return
	}

	out.Stdout = ""
	out.Stderr = ""
	s <- out
	return
}

/*
功能描述：巡检报告－－状态列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_state_listHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	var err error
	var sql string
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_state_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	error_msg = "获取巡检报告－－获取状态统计信息ID号为[" + r.FormValue("inspection_report_id") + "]－－"

	//判断巡检报告inspection_report_id号合法性
	inspection_report_id, err := strconv.Atoi(r.FormValue("inspection_report_id"))
	if err != nil {
		error_msg = error_msg + "巡检报告id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取数据
	data_chan := make(chan Inspection_report_stateData)
	go inspection_report_state_record(inspection_report_id, sql_sort_limit(r), data_chan)

	//异步获取总记录数
	sql = "SELECT COUNT(1) AS num FROM inspection_report_state WHERE inspection_report_id=" + fmt.Sprintf("%d", inspection_report_id)
	total_chan := make(chan Totalnum)
	go gettotalnum(sql, total_chan)

	//返回异步获取数据结果
	data := <-data_chan
	if data.Err != "" {
		error_msg = error_msg + data.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//返回异步获取总记录数
	total := <-total_chan
	if total.Err == "" {
		data.Total = total.Total
	} else {
		error_msg = error_msg + data.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：获取巡检报告－－索引统计信息

参数说明：
inspection_report_id   -- 巡检报告的id号
sql_sort_limit         -- 需要分页sql语句

返回值说明：
data_chan -- chan Inspection_report_indexData
*/

func inspection_report_state_record(inspection_report_id int, sql_sort_limit string, data_chan chan Inspection_report_stateData) {
	var err error
	var sql string
	var rec Inspection_report_state
	var data Inspection_report_stateData = Inspection_report_stateData{}
	data.Rows = make([]Inspection_report_state, 0)
	data.Total = 0
	data.Err = ""

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		data.Err = "连接数据库失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer conn.Close()

	sql = `
    SELECT
		id,
		subject,
		val
	FROM 
		inspection_report_state
	WHERE
		inspection_report_id=$1
    ` + sql_sort_limit

	rows, err := conn.Query(sql, inspection_report_id)
	if err != nil {
		data.Err = "查询资料失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&rec.Id, &rec.Subject, &rec.Val)
		if err != nil {
			data.Err = "提取数据失败－－详情：" + err.Error()
			data_chan <- data
			return
		}
		data.Rows = append(data.Rows, rec)
		data.Total = data.Total + 1
	}

	data_chan <- data
	return
}

/*
功能描述：巡检报告－－角色统计

参数说明：
inspection_report_id  -- 巡检报表－系统编号
row －－ 节点资料

返回值说明：
s -- 通道返回一个Stdout_and_stderr结构体
*/

//定义角色记录struct
type Inspection_report_role struct {
	Id                int    `json:"id"`
	Rolname           string `json:"rolname"`
	Rolcomment        string `json:"rolcomment"`
	Rolsuper          string `json:"rolsuper"`
	Rolcreaterole     string `json:"rolcreaterole"`
	Rolcreatedb       string `json:"rolcreatedb"`
	Rolcanlogin       string `json:"rolcanlogin"`
	Rolreplication    string `json:"rolreplication"`
	Rolconnlimit      int    `json:"rolconnlimit"`
	Rolpassword_state string `json:"rolpassword_state"`
	Rolvaliduntil     string `json:"rolvaliduntil"`
	Datnum            int64  `json:"datnum"`
	Tablenum          int64  `json:"tablenum"`
	Indexnum          int64  `json:"indexnum"`
}

//定义列表返回的struct
type Inspection_report_roleData struct {
	Total int                      `json:"total"`
	Rows  []Inspection_report_role `json:"rows"`
	Err   string                   `json:"err"`
}

func inspection_report_role_make(inspection_report_id int, row Row, s chan Stdout_and_stderr) {
	var err error
	var error_msg string
	//定义返回的struct
	var out Stdout_and_stderr
	var rec Inspection_report_role
	var sql string

	out.Stdout = ""
	out.Stderr = ""
	error_msg = "角色统计－－"

	//连接pgcluster数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		out.Stderr = error_msg + "连接pgcluster数据库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer conn.Close()

	//连接要统计的节点
	var nodeconn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = row.Host
	config.User = row.Pg_user
	config.Password = row.Pg_password
	config.Database = row.Pg_database
	config.Port = row.Pg_port

	nodeconn, err = pgx.Connect(config)
	if err != nil {
		out.Stderr = error_msg + "连接统计库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer nodeconn.Close()

	sql = `
	SELECT
		pg_authid.rolname,coalesce(pg_shdescription.description,'') AS rolcomment,
		CASE WHEN pg_authid.rolsuper THEN '是' ELSE '否' END AS rolsuper,CASE WHEN pg_authid.rolcreaterole THEN '是' ELSE '否' END AS rolcreaterole,
		CASE WHEN pg_authid.rolcreaterole THEN '是' ELSE '否' END AS rolcreaterole,CASE WHEN pg_authid.rolcreatedb THEN '是' ELSE '否' END AS rolcreatedb,
		CASE WHEN pg_authid.rolcanlogin THEN '是' ELSE '否' END AS rolcanlogin,CASE WHEN pg_authid.rolreplication THEN '是' ELSE '否' END AS rolreplication,
		pg_authid.rolconnlimit,CASE WHEN char_length(pg_authid.rolpassword)=35 AND substring(pg_authid.rolpassword from 1 for 3)='md5' THEN '加密' WHEN pg_authid.rolpassword IS NOT NULL THEN '未加密' ELSE '无密码' END AS rolpassword_state,
		COALESCE(pg_authid.rolvaliduntil::TEXT,'') AS rolvaliduntil 
	FROM
		pg_catalog.pg_authid AS pg_authid
		LEFT OUTER JOIN pg_catalog.pg_shdescription AS pg_shdescription ON pg_shdescription.objoid=pg_authid.oid
		LEFT OUTER JOIN (
		    SELECT 
			    pg_class.oid 
			FROM 
			    pg_catalog.pg_class AS pg_class
				INNER JOIN pg_catalog.pg_namespace AS pg_namespace ON pg_class.relnamespace=pg_namespace.oid  
			WHERE
				pg_class.relname='pg_tablespace' 
				AND pg_namespace.nspname='pg_authid' 
		) AS classoid ON classoid.oid=pg_shdescription.classoid
	ORDER BY
		pg_authid.rolname
	`
	rows, err := nodeconn.Query(sql)
	if err != nil {
		out.Stderr = error_msg + "查询资料失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(
			&rec.Rolname, &rec.Rolcomment,
			&rec.Rolsuper, &rec.Rolcreaterole,
			&rec.Rolcreaterole, &rec.Rolcreatedb,
			&rec.Rolcanlogin, &rec.Rolreplication,
			&rec.Rolconnlimit, &rec.Rolpassword_state,
			&rec.Rolvaliduntil)
		if err != nil {
			out.Stderr = error_msg + "提取数据失败－－详情：" + err.Error()
			s <- out
			return
		}
		sql = `
	    INSERT INTO inspection_report_role
	    (
	        inspection_report_id,
			rolname,rolcomment, 
			rolsuper,rolcreaterole,
			rolcreatedb,rolcanlogin,
			rolreplication,rolconnlimit,
			rolpassword_state,rolvaliduntil
	    )
		VALUES
		(
			$1,
			$2,$3,
			$4,$5,
			$6,$7,
			$8,$9,
			$10,NULLIF($11,'')::TIMESTAMP
		) 
	    `
		_, err = conn.Exec(sql,
			inspection_report_id,
			rec.Rolname, rec.Rolcomment,
			rec.Rolsuper, rec.Rolcreaterole,
			rec.Rolcreatedb, rec.Rolcanlogin,
			rec.Rolreplication, rec.Rolconnlimit,
			rec.Rolpassword_state, rec.Rolvaliduntil)

		if err != nil {
			out.Stderr = error_msg + "插入数据失败－－详情：" + err.Error()
			s <- out
			return
		}
	}

	out.Stdout = ""
	out.Stderr = ""
	s <- out
	return
}

/*
功能描述：巡检报告－－角色列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_role_listHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	var err error
	var sql string
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_role_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	error_msg = "获取巡检报告－－获取角色统计信息ID号为[" + r.FormValue("inspection_report_id") + "]－－"

	//判断巡检报告inspection_report_id号合法性
	inspection_report_id, err := strconv.Atoi(r.FormValue("inspection_report_id"))
	if err != nil {
		error_msg = error_msg + "巡检报告ID号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取数据
	data_chan := make(chan Inspection_report_roleData)
	go inspection_report_role_record(inspection_report_id, sql_sort_limit(r), data_chan)

	//异步获取总记录数
	sql = "SELECT COUNT(1) AS num FROM inspection_report_role WHERE inspection_report_id=" + fmt.Sprintf("%d", inspection_report_id)
	total_chan := make(chan Totalnum)
	go gettotalnum(sql, total_chan)

	//返回异步获取数据结果
	data := <-data_chan
	if data.Err != "" {
		error_msg = error_msg + data.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//返回异步获取总记录数
	total := <-total_chan
	if total.Err == "" {
		data.Total = total.Total
	} else {
		error_msg = error_msg + total.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：获取巡检报告－－角色统计信息

参数说明：
inspection_report_id   -- 巡检报告的id号
sql_sort_limit         -- 需要分页sql语句

返回值说明：
data_chan -- chan Inspection_report_roleData
*/

func inspection_report_role_record(inspection_report_id int, sql_sort_limit string, data_chan chan Inspection_report_roleData) {
	var err error
	var sql string
	var rec Inspection_report_role
	var data Inspection_report_roleData = Inspection_report_roleData{}
	data.Rows = make([]Inspection_report_role, 0)
	data.Total = 0
	data.Err = ""

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		data.Err = "连接数据库失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer conn.Close()

	sql = `
    SELECT
		id,rolname,rolcomment,
		rolsuper,rolsuper,
		rolcreaterole,rolcreatedb,
		rolcanlogin,rolreplication,
		rolconnlimit,rolpassword_state,
		COALESCE(rolvaliduntil::text,'') AS rolvaliduntil,COALESCE(datnum,0) AS datnum,
		COALESCE(tablenum,0) AS tablenum_show,COALESCE(indexnum,0) AS indexnum_show
	FROM 
		inspection_report_role
	WHERE
		inspection_report_id=$1
    ` + sql_sort_limit

	rows, err := conn.Query(sql, inspection_report_id)
	if err != nil {
		data.Err = "查询资料失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(
			&rec.Id,
			&rec.Rolname, &rec.Rolcomment,
			&rec.Rolsuper, &rec.Rolcreaterole,
			&rec.Rolcreaterole, &rec.Rolcreatedb,
			&rec.Rolcanlogin, &rec.Rolreplication,
			&rec.Rolconnlimit, &rec.Rolpassword_state,
			&rec.Rolvaliduntil, &rec.Datnum,
			&rec.Tablenum, &rec.Indexnum)
		if err != nil {
			data.Err = "提取数据失败－－详情：" + err.Error()
			data_chan <- data
			return
		}
		data.Rows = append(data.Rows, rec)
		data.Total = data.Total + 1
	}

	data_chan <- data
	return
}

/*
功能描述：获取巡检报告－－角色其它字段异步更新

参数说明：
inspection_report_id   -- 巡检报告的id号

返回值说明：无

*/

func inspection_report_role_update(inspection_report_id int) {
	var err error
	remote_ip := "127.0.0.1"
	modlename := "inspection_report_role_update"
	username := "admin"
	var sql string
	error_msg := "巡检报告－－角色其它字更新inspection_report_id为[" + fmt.Sprintf("%d", inspection_report_id) + "]－－"

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		error_msg := error_msg + "连接数据库出错－－详情：" + err.Error()
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql = `
	UPDATE 
		inspection_report_role
	SET
		datnum=0,tablenum=0,indexnum=0
	WHERE
		inspection_report_role.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	
	UPDATE 
		inspection_report_role
	SET
		datnum=t.num
	FROM
		(SELECT COUNT(1) AS num,datdba FROM inspection_report_database WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + ` GROUP BY datdba) AS t
	WHERE
		inspection_report_role.rolname=t.datdba
		AND inspection_report_role.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	
	UPDATE 
		inspection_report_role
	SET
		tablenum=t.num
	FROM
		(SELECT COUNT(1) AS num,tableowner FROM inspection_report_table WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + ` GROUP BY tableowner) AS t
	WHERE
		inspection_report_role.rolname=t.tableowner
		AND inspection_report_role.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	
	UPDATE 
		inspection_report_role
	SET
		indexnum=t.num
	FROM
		(SELECT COUNT(1) AS num,indexowner FROM inspection_report_index WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + ` GROUP BY indexowner) AS t
	WHERE
		inspection_report_role.rolname=t.indexowner
		AND inspection_report_role.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `
	 `
	_, err = conn.Exec(sql)

	if err != nil {
		error_msg := error_msg + "更新数据出错－－详情：" + err.Error()
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

}

/*
功能描述：巡检报告－－表空间统计

参数说明：
inspection_report_id  -- 巡检报表－系统编号
row －－ 节点资料

返回值说明：
s -- 通道返回一个Stdout_and_stderr结构体
*/

//定义表空间记录struct
type Inspection_report_tablespace struct {
	Id         int    `json:"id"`
	Spcname    string `json:"spcname"`
	Spccomment string `json:"spccomment"`
	Spcowner   string `json:"spcowner"`
	Location   string `json:"location"`
	Spcsize    string `json:"spcsize"`
	Tablenum   int64  `json:"tablenum"`
	Indexnum   int64  `json:"indexnum"`
}

//定义列表返回的struct
type Inspection_report_tablespaceData struct {
	Total int                            `json:"total"`
	Rows  []Inspection_report_tablespace `json:"rows"`
	Err   string                         `json:"err"`
}

func inspection_report_tablespace_make(inspection_report_id int, row Row, s chan Stdout_and_stderr) {
	var err error
	var error_msg string
	//定义返回的struct
	var out Stdout_and_stderr

	var rec Inspection_report_tablespace
	var sql string

	out.Stdout = ""
	out.Stderr = ""
	error_msg = "表空间统计－－"

	//连接pgcluster数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		out.Stderr = error_msg + "连接pgcluster数据库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer conn.Close()

	//连接要统计的节点
	var nodeconn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = row.Host
	config.User = row.Pg_user
	config.Password = row.Pg_password
	config.Database = row.Pg_database
	config.Port = row.Pg_port

	nodeconn, err = pgx.Connect(config)
	if err != nil {
		out.Stderr = error_msg + "连接统计库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer nodeconn.Close()

	sql = `
	SELECT
		pg_tablespace.spcname,
		coalesce(pg_shdescription.description,'') AS spccomment,
		pg_authid.rolname AS spcowner,
		pg_catalog.pg_tablespace_location(pg_tablespace.oid) AS location,
		pg_catalog.pg_tablespace_size(pg_tablespace.oid)::text AS spcsize
	FROM
		pg_catalog.pg_tablespace AS pg_tablespace
		INNER JOIN pg_catalog.pg_authid AS pg_authid ON pg_tablespace.spcowner=pg_authid.oid
		LEFT OUTER JOIN pg_catalog.pg_shdescription AS pg_shdescription ON pg_shdescription.objoid=pg_tablespace.oid
		LEFT OUTER JOIN (
		    SELECT 
			    pg_class.oid 
			FROM 
			    pg_catalog.pg_class AS pg_class
				INNER JOIN pg_catalog.pg_namespace AS pg_namespace ON pg_class.relnamespace=pg_namespace.oid  
			WHERE
				pg_class.relname='pg_tablespace' 
				AND pg_namespace.nspname='pg_catalog' 
		) AS classoid ON classoid.oid=pg_shdescription.classoid
	ORDER BY
		pg_tablespace.spcname
	`

	rows, err := nodeconn.Query(sql)
	if err != nil {
		out.Stderr = error_msg + "查询资料失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&rec.Spcname, &rec.Spccomment, &rec.Spcowner, &rec.Location, &rec.Spcsize)
		if err != nil {
			out.Stderr = error_msg + "提取数据失败－－详情：" + err.Error()
			s <- out
			return
		}
		sql = `
	    INSERT INTO inspection_report_tablespace
	    (
	        inspection_report_id,
			spcname,spccomment,
			spcowner,location,
			spcsize
	    )
		VALUES
		(
			$1,
			$2,$3,
			$4,$5,
			$6
		) 
	    `
		_, err = conn.Exec(sql,
			inspection_report_id,
			rec.Spcname, rec.Spccomment,
			rec.Spcowner, rec.Location,
			rec.Spcsize)

		if err != nil {
			out.Stderr = error_msg + "插入数据失败－－详情：" + err.Error()
			s <- out
			return
		}
	}

	out.Stdout = ""
	out.Stderr = ""
	s <- out
	return
}

/*
功能描述：巡检报告－－表空间列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_tablespace_listHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	var err error
	var sql string
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_tablespace_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	error_msg = "获取巡检报告－－获取表空间统计信息ID号为[" + r.FormValue("inspection_report_id") + "]－－"

	//判断巡检报告inspection_report_id号合法性
	inspection_report_id, err := strconv.Atoi(r.FormValue("inspection_report_id"))
	if err != nil {
		error_msg = error_msg + "巡检报告id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取数据
	data_chan := make(chan Inspection_report_tablespaceData)
	go inspection_report_tablespace_record(inspection_report_id, sql_sort_limit(r), data_chan)

	//异步获取总记录数
	sql = "SELECT COUNT(1) AS num FROM inspection_report_tablespace WHERE inspection_report_id=" + fmt.Sprintf("%d", inspection_report_id)
	total_chan := make(chan Totalnum)
	go gettotalnum(sql, total_chan)

	//返回异步获取数据结果
	data := <-data_chan
	if data.Err != "" {
		error_msg = error_msg + data.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//返回异步获取总记录数
	total := <-total_chan
	if total.Err == "" {
		data.Total = total.Total
	} else {
		error_msg = error_msg + total.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：获取巡检报告－－表空间统计信息

参数说明：
inspection_report_id   -- 巡检报告的id号
sql_sort_limit         -- 需要分页sql语句

返回值说明：
data_chan -- chan Inspection_report_tablespaceData
*/

func inspection_report_tablespace_record(inspection_report_id int, sql_sort_limit string, data_chan chan Inspection_report_tablespaceData) {
	var err error
	var sql string
	var rec Inspection_report_tablespace
	var data Inspection_report_tablespaceData = Inspection_report_tablespaceData{}
	data.Rows = make([]Inspection_report_tablespace, 0)
	data.Total = 0
	data.Err = ""

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		data.Err = "连接数据库失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer conn.Close()

	sql = `
    SELECT
		id,
		spcname,spccomment,
		spcowner,location,
		pg_catalog.pg_size_pretty(spcsize) AS spcsize_show,COALESCE(tablenum,0) AS tablenum_show,
		COALESCE(indexnum,0) AS indexnum_show
	FROM 
		inspection_report_tablespace
	WHERE
		inspection_report_id=$1
    ` + sql_sort_limit

	rows, err := conn.Query(sql, inspection_report_id)
	if err != nil {
		data.Err = "查询资料失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&rec.Id, &rec.Spcname, &rec.Spccomment, &rec.Spcowner, &rec.Location, &rec.Spcsize, &rec.Tablenum, &rec.Indexnum)
		if err != nil {
			data.Err = "提取数据失败－－详情：" + err.Error()
			data_chan <- data
			return
		}
		data.Rows = append(data.Rows, rec)
		data.Total = data.Total + 1
	}

	data_chan <- data
	return
}

/*
功能描述：获取巡检报告－－表空间其它字段异步更新

参数说明：
inspection_report_id   -- 巡检报告的id号

返回值说明：无

*/

func inspection_report_tablespace_update(inspection_report_id int) {
	var err error
	remote_ip := "127.0.0.1"
	modlename := "inspection_report_tablespace_update"
	username := "admin"
	var sql string
	error_msg := "巡检报告－－表空间其它字更新inspection_report_id为[" + fmt.Sprintf("%d", inspection_report_id) + "]－－"

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		error_msg := error_msg + "连接数据库出错－－详情：" + err.Error()
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql = `
	UPDATE 
		inspection_report_tablespace
	SET
		tablenum=0,indexnum=0
	WHERE
		inspection_report_tablespace.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	
	UPDATE 
		inspection_report_tablespace
	SET
		tablenum=t.num
	FROM
		(SELECT COUNT(1) AS num,tablespace FROM inspection_report_table WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + ` GROUP BY tablespace) AS t
	WHERE
		inspection_report_tablespace.spcname=t.tablespace
		AND inspection_report_tablespace.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	
	UPDATE 
		inspection_report_tablespace
	SET
		indexnum=t.num
	FROM
		(SELECT COUNT(1) AS num,tablespace FROM inspection_report_index WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + ` GROUP BY tablespace) AS t
	WHERE
		inspection_report_tablespace.spcname=t.tablespace
		AND inspection_report_tablespace.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `
	 `
	_, err = conn.Exec(sql)

	if err != nil {
		error_msg := error_msg + "更新数据出错－－详情：" + err.Error()
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

}

/*
功能描述：巡检报告－－数据库统计

参数说明：
inspection_report_id  -- 巡检报表－系统编号
row －－ 节点资料
database --要统计的数据库名
count_system_obj--控制是否统计系统对象--值分别是 “统计”，“不统计”

返回值说明：
s -- 通道返回一个Stdout_and_stderr结构体
*/

//定义数据库记录struct
type Inspection_report_database struct {
	Id            int    `json:"id"`
	Datname       string `json:"datname"`
	Datcomment    string `json:"datcomment"`
	Datdba        string `json:"datdba"`
	Encoding      string `json:"encoding"`
	Datcollate    string `json:"datcollate"`
	Datctype      string `json:"datctype"`
	Datistemplate string `json:"datistemplate"`
	Datallowconn  string `json:"datallowconn"`
	Datconnlimit  int    `json:"datconnlimit"`
	Dattablespace string `json:"dattablespace"`
	Datsize       string `json:"datsize"`
	Tablenum      int64  `json:"tablenum"`
	Indexnum      int64  `json:"indexnum"`
}

//定义列表返回的struct
type Inspection_report_databaseData struct {
	Total int                          `json:"total"`
	Rows  []Inspection_report_database `json:"rows"`
	Err   string                       `json:"err"`
}

//定义“巡检报告－－数据库统计”返回的数据库列表
type DatabaseData struct {
	Total int      `json:"total"`
	Rows  []string `json:"rows"`
	Err   string   `json:"err"`
}

func inspection_report_database_make(inspection_report_id int, database string, count_system_obj string, row Row, s chan DatabaseData) {
	var err error
	var error_msg string
	//定义返回的struct
	var out DatabaseData

	out.Rows = make([]string, 0)
	out.Total = 0
	out.Err = ""

	var rec Inspection_report_database
	var sql string

	error_msg = "数据库统计－－"

	//连接pgcluster数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		out.Err = error_msg + "连接pgcluster数据库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer conn.Close()

	//连接要统计的节点
	var nodeconn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = row.Host
	config.User = row.Pg_user
	config.Password = row.Pg_password
	config.Database = row.Pg_database
	config.Port = row.Pg_port

	nodeconn, err = pgx.Connect(config)
	if err != nil {
		out.Err = error_msg + "连接统计库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer nodeconn.Close()

	where := " WHERE 1=1 "
	if database != "" {
		where = where + " AND pg_database.datname='" + sql_data_encode(database) + "'"
	} else if count_system_obj == "不统计" {
		where = where + " AND pg_database.datname NOT IN ('template0','template1')"
	}

	sql = `
	SELECT
		pg_database.datname,coalesce(pg_shdescription.description,'') AS datcomment,
		pg_authid.rolname AS datdba,pg_encoding_to_char(pg_database.encoding) AS encoding,
		pg_database.datcollate,pg_database.datctype,
		CASE WHEN pg_database.datistemplate THEN '是' ELSE '否' END AS datistemplate,CASE WHEN pg_database.datallowconn THEN '是' ELSE '否' END AS datallowconn,
		pg_database.datconnlimit,pg_tablespace.spcname AS dattablespace,
		pg_catalog.pg_database_size(pg_database.oid)::text AS datsize
	FROM
		pg_catalog.pg_database AS pg_database 
		INNER JOIN pg_catalog.pg_tablespace AS pg_tablespace ON pg_tablespace.oid=pg_database.dattablespace
		INNER JOIN pg_catalog.pg_authid AS pg_authid ON pg_authid.oid=pg_database.datdba
		LEFT OUTER JOIN pg_catalog.pg_shdescription AS pg_shdescription ON pg_shdescription.objoid=pg_database.oid
		LEFT OUTER JOIN (
		    SELECT 
			    pg_class.oid 
			FROM 
			    pg_catalog.pg_class AS pg_class
				INNER JOIN pg_catalog.pg_namespace AS pg_namespace ON pg_class.relnamespace=pg_namespace.oid  
			WHERE
				pg_class.relname='pg_database' 
				AND pg_namespace.nspname='pg_catalog' 
		) AS classoid ON classoid.oid=pg_shdescription.classoid
	` + where + `
	ORDER BY
		pg_database.datname
	`
	rows, err := nodeconn.Query(sql)
	if err != nil {
		out.Err = error_msg + "查询资料失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(
			&rec.Datname, &rec.Datcomment,
			&rec.Datdba, &rec.Encoding,
			&rec.Datcollate, &rec.Datctype,
			&rec.Datistemplate, &rec.Datallowconn,
			&rec.Datconnlimit, &rec.Dattablespace,
			&rec.Datsize)
		if err != nil {
			out.Err = error_msg + "提取数据失败－－详情：" + err.Error()
			s <- out
			return
		}
		sql = `
	    INSERT INTO inspection_report_database
	    (
			inspection_report_id,
			datname,datcomment,
			datdba,encoding,
			datcollate,datctype,
			datistemplate,datallowconn,
			datconnlimit,dattablespace,
			datsize
	    )
		VALUES
		(
			$1,
			$2,$3,
			$4,$5,
			$6,$7,
			$8,$9,
			$10,$11,
			$12
		) 
	    `

		_, err = conn.Exec(sql,
			inspection_report_id,
			rec.Datname, rec.Datcomment,
			rec.Datdba, rec.Encoding,
			rec.Datcollate, rec.Datctype,
			rec.Datistemplate, rec.Datallowconn,
			rec.Datconnlimit, rec.Dattablespace,
			rec.Datsize)

		if err != nil {
			out.Err = error_msg + "插入数据失败－－详情：" + err.Error()
			s <- out
			return
		}

		if rec.Datallowconn == "是" {
			out.Rows = append(out.Rows, rec.Datname)
			out.Total = out.Total + 1
		}
	}

	out.Err = ""
	s <- out
	return
}

/*
功能描述：巡检报告－－数据库列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_database_listHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	var err error
	var sql string
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_database_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	error_msg = "获取巡检报告－－获取数据库统计信息ID号为[" + r.FormValue("inspection_report_id") + "]－－"

	//判断巡检报告inspection_report_id号合法性
	inspection_report_id, err := strconv.Atoi(r.FormValue("inspection_report_id"))
	if err != nil {
		error_msg = error_msg + "巡检报告id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取数据
	data_chan := make(chan Inspection_report_databaseData)
	go inspection_report_database_record(inspection_report_id, sql_sort_limit(r), data_chan)

	//异步获取总记录数
	sql = "SELECT COUNT(1) AS num FROM inspection_report_database WHERE inspection_report_id=" + fmt.Sprintf("%d", inspection_report_id)
	total_chan := make(chan Totalnum)
	go gettotalnum(sql, total_chan)

	//返回异步获取数据结果
	data := <-data_chan
	if data.Err != "" {
		error_msg = error_msg + data.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//返回异步获取总记录数
	total := <-total_chan
	if total.Err == "" {
		data.Total = total.Total
	} else {
		error_msg = error_msg + total.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：获取巡检报告－－数据库统计信息

参数说明：
inspection_report_id   -- 巡检报告的id号
sql_sort_limit         -- 需要分页sql语句

返回值说明：
data_chan -- chan Inspection_report_databaseData
*/

func inspection_report_database_record(inspection_report_id int, sql_sort_limit string, data_chan chan Inspection_report_databaseData) {
	var err error
	var sql string
	var rec Inspection_report_database
	var data Inspection_report_databaseData = Inspection_report_databaseData{}
	data.Rows = make([]Inspection_report_database, 0)
	data.Total = 0
	data.Err = ""

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		data.Err = "连接数据库失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer conn.Close()

	sql = `
    SELECT
		id,
		datname,datcomment,
		datdba,encoding,
		datcollate,datctype,
		datistemplate,datallowconn,
		datconnlimit,dattablespace,
		pg_catalog.pg_size_pretty(datsize) AS datsize_show,COALESCE(tablenum,0) AS tablenum_show,
		COALESCE(indexnum,0) AS indexnum_show
	FROM 
		inspection_report_database
	WHERE
		inspection_report_id=$1
    ` + sql_sort_limit

	rows, err := conn.Query(sql, inspection_report_id)
	if err != nil {
		data.Err = "查询资料失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(
			&rec.Id,
			&rec.Datname, &rec.Datcomment,
			&rec.Datdba, &rec.Encoding,
			&rec.Datcollate, &rec.Datctype,
			&rec.Datistemplate, &rec.Datallowconn,
			&rec.Datconnlimit, &rec.Dattablespace,
			&rec.Datsize, &rec.Tablenum,
			&rec.Indexnum)
		if err != nil {
			data.Err = "提取数据失败－－详情：" + err.Error()
			data_chan <- data
			return
		}
		data.Rows = append(data.Rows, rec)
		data.Total = data.Total + 1
	}

	data_chan <- data
	return
}

/*
功能描述：获取巡检报告－－数据库其它字段异步更新

参数说明：
inspection_report_id   -- 巡检报告的id号

返回值说明：无

*/

func inspection_report_database_update(inspection_report_id int) {
	var err error
	remote_ip := "127.0.0.1"
	modlename := "inspection_report_database_update"
	username := "admin"
	var sql string
	error_msg := "巡检报告－－数据库其它字更新inspection_report_id为[" + fmt.Sprintf("%d", inspection_report_id) + "]－－"

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		error_msg := error_msg + "连接数据库出错－－详情：" + err.Error()
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql = `
	UPDATE 
		inspection_report_database
	SET
		tablenum=0,indexnum=0
	WHERE
		inspection_report_database.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	
	UPDATE 
		inspection_report_database
	SET
		tablenum=t.num
	FROM
		(SELECT COUNT(1) AS num,datname FROM inspection_report_table WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + ` GROUP BY datname) AS t
	WHERE
		inspection_report_database.datname=t.datname
		AND inspection_report_database.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	
	UPDATE 
		inspection_report_database
	SET
		indexnum=t.num
	FROM
		(SELECT COUNT(1) AS num,datname FROM inspection_report_index WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + ` GROUP BY datname) AS t
	WHERE
		inspection_report_database.datname=t.datname
		AND inspection_report_database.inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `
	 `
	_, err = conn.Exec(sql)

	if err != nil {
		error_msg := error_msg + "更新数据出错－－详情：" + err.Error()
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

}

/*
功能描述：巡检报告－－数据表统计

参数说明：
inspection_report_id  -- 巡检报表－系统编号
count_system_obj --控制是否统计系统对象--值分别是 “统计”，“不统计”
row －－ 节点资料
dattablespace --数据库默认表空间

返回值说明：
s -- 通道返回一个Stdout_and_stderr结构体
*/

//定义数据表记录struct

type Inspection_report_table struct {
	Id               int    `json:"id"`
	Datname          string `json:"datname"`
	Schemaname       string `json:"schemaname"`
	Tablename        string `json:"tablename"`
	Tabletype        string `json:"tabletype"`
	Tablecomment     string `json:"tablecomment"`
	Tableowner       string `json:"tableowner"`
	Tablespace       string `json:"tablespace"`
	Reltuples        int64  `json:"reltuples"`
	Rownum           string `json:"rownum"`
	Rownum_deviation string `json:"rownum_deviation"`
	Relationsize     string `json:"relationsize"`
	Relpages         int64  `json:"relpages"`
	Row_of_size      string `json:"row_of_size"`
	Indexnum         int    `json:"indexnum"`
	Indexsize        string `json:"indexsize"`
	Tablesize        string `json:"tablesize"`
	Seq_scan         int64  `json:"seq_scan"`
	Seq_tup_read     int64  `json:"seq_tup_read"`
	Idx_scan         int64  `json:"idx_scan"`
	Idx_tup_fetch    int64  `json:"idx_tup_fetch"`
	Last_vacuum      string `json:"last_vacuum"`
	Last_autovacuum  string `json:"last_autovacuum"`
	Last_analyze     string `json:"last_analyze"`
	Last_autoanalyze string `json:"last_autoanalyze"`
}

//定义列表返回的struct
type Inspection_report_tableData struct {
	Total int                       `json:"total"`
	Rows  []Inspection_report_table `json:"rows"`
	Err   string                    `json:"err"`
}

func inspection_report_table_make(inspection_report_id int, count_system_obj string, row Row, s chan Stdout_and_stderr) {
	var err error
	var error_msg string
	//定义返回的struct
	var out Stdout_and_stderr
	out.Stdout = ""
	out.Stderr = ""

	var rec Inspection_report_table
	var sql string

	error_msg = "数据表统计－－统计库为[" + row.Pg_database + "]－－"

	//连接pgcluster数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		out.Stderr = error_msg + "连接pgcluster数据库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer conn.Close()

	//连接要统计的节点
	var nodeconn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = row.Host
	config.User = row.Pg_user
	config.Password = row.Pg_password
	config.Database = row.Pg_database
	config.Port = row.Pg_port

	nodeconn, err = pgx.Connect(config)
	if err != nil {
		out.Stderr = error_msg + "连接统计库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer nodeconn.Close()

	//获取数据库默认表空间
	sql = `
	SELECT
		pg_tablespace.spcname AS dattablespace
	FROM
		pg_catalog.pg_database AS pg_database 
		INNER JOIN pg_catalog.pg_tablespace AS pg_tablespace ON pg_tablespace.oid=pg_database.dattablespace
	WHERE
		pg_database.datname=$1
	`
	rows, err := nodeconn.Query(sql, row.Pg_database)
	if err != nil {
		out.Stderr = error_msg + "查询数据库默认表空间失败－－详情：" + err.Error()
		s <- out
		return
	}
	var dattablespace string
	if rows.Next() {
		err = rows.Scan(&dattablespace)
		if err != nil {
			out.Stderr = error_msg + "获取数据库默认表空间数据失败－－详情：" + err.Error()
			s <- out
			return
		}
	}
	rows.Close()

	where := " "
	if count_system_obj == "不统计" {
		where = where + " AND pg_namespace.nspname NOT IN ('pg_catalog','information_schema')"
	}

	//获取该数据库的所有数据表

	sql = `
	SELECT
		pg_namespace.nspname AS schemaname ,pg_class.relname AS tablename,
		CASE WHEN pg_class.relkind='r' THEN '数据表' ELSE '物化视图' END AS tabletype,COALESCE(pg_description.description,'') AS tablecomment, 
		pg_authid.rolname AS tableowner,COALESCE(pg_tablespace.spcname,'` + dattablespace + `') AS tablespace,
		pg_class.reltuples::bigint,pg_catalog.pg_table_size(pg_class.oid)::text AS relationsize,
	    pg_class.relpages,CASE WHEN pg_class.reltuples>0 THEN pg_table_size(pg_class.oid)/pg_class.reltuples ELSE pg_table_size(pg_class.oid) END::bigint::text AS row_of_size,
		COALESCE(indexnum.indexnum,0) AS indexnum,pg_catalog.pg_indexes_size(pg_class.oid)::text AS indexsize,
		pg_catalog.pg_total_relation_size(pg_class.oid)::text AS tablesize,
		COALESCE(pg_stat_all_tables.seq_scan,0) AS seq_scan, COALESCE(pg_stat_all_tables.seq_tup_read,0) AS seq_tup_read,
		COALESCE(pg_stat_all_tables.idx_scan,0) AS idx_scan, COALESCE(pg_stat_all_tables.idx_tup_fetch,0) AS idx_tup_fetch,
		COALESCE(pg_stat_all_tables.last_vacuum::TIMESTAMP(0)::TEXT,'') AS last_vacuum, COALESCE(pg_stat_all_tables.last_autovacuum::TIMESTAMP(0)::TEXT,'') AS last_autovacuum,
		COALESCE(pg_stat_all_tables.last_analyze::TIMESTAMP(0)::TEXT,'') AS last_analyze, COALESCE(pg_stat_all_tables.last_autoanalyze::TIMESTAMP(0)::TEXT,'') AS last_autoanalyze
	FROM
		pg_catalog.pg_class AS pg_class
		INNER JOIN pg_catalog.pg_namespace AS pg_namespace ON pg_namespace.oid=pg_class.relnamespace
		LEFT OUTER JOIN pg_catalog.pg_description AS pg_description ON pg_description.objoid=pg_class.oid AND pg_description.objsubid=0
		LEFT OUTER JOIN (
		    SELECT 
			    pg_class.oid 
			FROM 
			    pg_catalog.pg_class AS pg_class
				INNER JOIN pg_catalog.pg_namespace AS pg_namespace ON pg_class.relnamespace=pg_namespace.oid  
			WHERE
				pg_class.relname='pg_class' 
				AND pg_namespace.nspname='pg_catalog' 
		) AS classoid ON classoid.oid=pg_description.classoid
		INNER JOIN pg_catalog.pg_authid AS pg_authid ON pg_authid.oid=pg_class.relowner
		LEFT OUTER JOIN pg_catalog.pg_tablespace AS pg_tablespace ON pg_tablespace.oid=pg_class.reltablespace
		LEFT OUTER JOIN (
			SELECT 
				COUNT(1) AS indexnum,
				indrelid 
			FROM
				pg_catalog.pg_index AS pg_index 
			GROUP BY
			 	pg_index.indrelid
		) AS indexnum ON indexnum.indrelid=pg_class.oid
		LEFT OUTER JOIN pg_catalog.pg_stat_all_tables AS pg_stat_all_tables ON pg_stat_all_tables.relid=pg_class.oid
	WHERE
		pg_class.relkind IN ('r','m')
		` + where + `
	`
	rows, err = nodeconn.Query(sql)
	if err != nil {
		out.Stderr = error_msg + "查询数据失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(
			&rec.Schemaname, &rec.Tablename,
			&rec.Tabletype, &rec.Tablecomment,
			&rec.Tableowner, &rec.Tablespace,
			&rec.Reltuples, &rec.Relationsize,
			&rec.Relpages, &rec.Row_of_size,
			&rec.Indexnum, &rec.Indexsize,
			&rec.Tablesize,
			&rec.Seq_scan, &rec.Seq_tup_read,
			&rec.Idx_scan, &rec.Idx_tup_fetch,
			&rec.Last_vacuum, &rec.Last_autovacuum,
			&rec.Last_analyze, &rec.Last_autoanalyze)

		if err != nil {
			out.Stderr = error_msg + "提取数据失败－－详情：" + err.Error()
			s <- out
			return
		}

		sql = `
	    INSERT INTO inspection_report_table
	    (
	        inspection_report_id,datname,
			schemaname,tablename,
			tabletype,tablecomment,
			tableowner,tablespace,
			reltuples,relationsize,
			rownum,rownum_deviation,
			relpages,row_of_size,
			indexnum,indexsize,
			tablesize,
			seq_scan,seq_tup_read,
			idx_scan,idx_tup_fetch,
			last_vacuum,last_autovacuum,
			last_analyze,last_autoanalyze
	    )
		VALUES
		(
			$1,$2,
			$3,$4,
			$5,$6,
			$7,$8,
			$9,$10,
			NULL,NULL,					
			$11,$12,
			$13,$14,		
			$15,
			$16,$17,
			$18,$19,
			NULLIF($20,'')::TIMESTAMP,NULLIF($21,'')::TIMESTAMP,
			NULLIF($22,'')::TIMESTAMP,NULLIF($23,'')::TIMESTAMP
		) 
	    `
		_, err = conn.Exec(sql,
			inspection_report_id, row.Pg_database,
			rec.Schemaname, rec.Tablename,
			rec.Tabletype, rec.Tablecomment,
			rec.Tableowner, rec.Tablespace,
			rec.Reltuples, rec.Relationsize,
			rec.Relpages, rec.Row_of_size,
			rec.Indexnum, rec.Indexsize,
			rec.Tablesize,
			rec.Seq_scan, rec.Seq_tup_read,
			rec.Idx_scan, rec.Idx_tup_fetch,
			rec.Last_vacuum, rec.Last_autovacuum,
			rec.Last_analyze, rec.Last_autoanalyze)

		if err != nil {
			out.Stderr = error_msg + "插入数据失败－－详情：" + err.Error()
			s <- out
			return
		}
		//go inspection_report_table_rownum_update(inspection_report_id, row, rec)
	}

	out.Stdout = ""
	out.Stderr = ""
	s <- out
	return
}

/*
功能描述：巡检报告－－用于异步更新每个表的记录数

参数说明：
inspection_report_id   -- 巡检报告id号
count_recordnum_processes --最大的并发数
noderow -- 结构类型 Table_rownum_update_row

返回值说明：无
*/
//节点行信息json结构

type Table_rownum_update_row struct {
	Host        string `json:"host"`
	Pg_port     uint16 `json:"pg_port"`
	Pg_database string `json:"pg_database"`
	Pg_user     string `json:"pg_user"`
	Pg_password string `json:"pg_password"`
	Schemaname  string `json:"schemaname"`
	Tablename   string `json:"tablename"`
}

func inspection_report_table_rownum_update(inspection_report_id int, count_recordnum_processes int, noderow Table_rownum_update_row) {
	var err error
	var sql string
	remote_ip := "127.0.0.1"
	modlename := "inspection_report_table_rownum_update"
	username := "admin"
	error_msg := "巡检报告－－更新每个表的记录数,巡检报告ID号为[" + fmt.Sprintf("%d", inspection_report_id) + "]－－"

	//判断是否生成表记录
	if count_recordnum_processes == 0 {
		return
	}
	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		error_msg = error_msg + "连接数据库失败，详情：" + err.Error()
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	var row Table_rownum_update_row
	row = noderow
	end := make(chan Stdout_and_stderr, count_recordnum_processes)
	i := 0

	sql = "SELECT datname,schemaname,tablename FROM inspection_report_table  WHERE inspection_report_id=$1"
	rows, err := conn.Query(sql, inspection_report_id)
	if err != nil {
		error_msg = error_msg + "查询数据失败－－详情：" + err.Error()
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	for rows.Next() {
		err = rows.Scan(&row.Pg_database, &row.Schemaname, &row.Tablename)
		if err != nil {
			error_msg = error_msg + "提取数据出错,详情：" + err.Error()
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		go inspection_report_table_rownum_update_run(inspection_report_id, row, end)
		i++
		//如果并发数用完就要处理结果
		if i == count_recordnum_processes {
			t := <-end
			if t.Stderr != "" {
				error_msg = error_msg + "更新表记录数出错－－" + t.Stderr
				go write_log(remote_ip, modlename, username, "Error", error_msg)
			}
			i--
		}
	}
	//循环完成还需要再处理没有完成的异步协程
	for j := 0; j < i; j++ {
		t := <-end
		if t.Stderr != "" {
			error_msg = error_msg + "更新表记录数出错－－" + t.Stderr
			go write_log(remote_ip, modlename, username, "Error", error_msg)
		}
	}
	defer rows.Close()
	sql = "UPDATE inspection_report SET count_finish='是' WHERE id=$1"
	_, err = conn.Exec(sql, inspection_report_id)

	if err != nil {
		error_msg = error_msg + "更新巡检报告统计状态为完成失败,详情：" + err.Error()
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	error_msg = error_msg + "更新完成"
	go write_log(remote_ip, modlename, username, "Log", error_msg)
	return
}

//用于异步更新每个表的记录数
func inspection_report_table_rownum_update_run(inspection_report_id int, row Table_rownum_update_row, s chan Stdout_and_stderr) {
	var err error
	//定义返回的struct
	var out Stdout_and_stderr
	out.Stdout = ""
	out.Stderr = ""

	error_msg := "要更新的数据表－－" + row.Host + ":" + fmt.Sprintf("%d", row.Pg_port) + "@" + row.Pg_database + "." + row.Schemaname + "." + row.Tablename + "－－"

	//连接要统计的节点
	var nodeconn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = row.Host
	config.User = row.Pg_user
	config.Password = row.Pg_password
	config.Database = row.Pg_database
	config.Port = row.Pg_port

	nodeconn, err = pgx.Connect(config)
	if err != nil {
		out.Stderr = error_msg + "连接统计库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer nodeconn.Close()

	var sql string
	var num int64
	sql = "SELECT COUNT(1) AS num FROM " + sql_data_encode(row.Schemaname) + "." + sql_data_encode(row.Tablename)
	rows, err := nodeconn.Query(sql)

	for rows.Next() {
		err = rows.Scan(&num)
		if err != nil {
			out.Stderr = error_msg + "提取数据出错,详情：" + err.Error()
			s <- out
			return
		}
	}
	defer rows.Close()

	//连接pgcluster数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		out.Stderr = error_msg + "连接pgcluster数据库出错,详情：" + err.Error()
		s <- out
		return
	}
	defer conn.Close()

	sql = "UPDATE inspection_report_table SET rownum=$1,rownum_deviation=$1 - reltuples,row_of_size=CASE WHEN $1>0 THEN relationsize/$1 ELSE relationsize END::bigint WHERE inspection_report_id=$2 AND datname=$3 AND schemaname=$4 AND tablename=$5"
	_, err = conn.Exec(sql, num, inspection_report_id, row.Pg_database, row.Schemaname, row.Tablename)

	if err != nil {
		out.Stderr = error_msg + "更新数据表出错,详情：" + err.Error()
		s <- out
		return
	}

	out.Stdout = ""
	out.Stderr = ""
	s <- out
	return
}

/*
功能描述：巡检报告－－数据表列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_table_listHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	var err error
	var sql string
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_table_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	error_msg = "获取巡检报告－－获取数据表统计信息ID号为[" + r.FormValue("inspection_report_id") + "]－－"

	//判断巡检报告inspection_report_id号合法性
	inspection_report_id, err := strconv.Atoi(r.FormValue("inspection_report_id"))
	if err != nil {
		error_msg = error_msg + "巡检报告id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取数据
	data_chan := make(chan Inspection_report_tableData)
	go inspection_report_table_record(inspection_report_id, sql_sort_limit(r), data_chan)

	//异步获取总记录数
	sql = "SELECT COUNT(1) AS num FROM inspection_report_table WHERE inspection_report_id=" + fmt.Sprintf("%d", inspection_report_id)
	total_chan := make(chan Totalnum)
	go gettotalnum(sql, total_chan)

	//返回异步获取数据结果
	data := <-data_chan
	if data.Err != "" {
		error_msg = error_msg + data.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//返回异步获取总记录数
	total := <-total_chan
	if total.Err == "" {
		data.Total = total.Total
	} else {
		error_msg = error_msg + total.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：获取巡检报告－－数据表统计信息

参数说明：
inspection_report_id   -- 巡检报告的id号
sql_sort_limit         -- 需要分页sql语句

返回值说明：
data_chan -- chan Inspection_report_tableData
*/

func inspection_report_table_record(inspection_report_id int, sql_sort_limit string, data_chan chan Inspection_report_tableData) {
	var err error
	var sql string
	var rec Inspection_report_table
	var data Inspection_report_tableData = Inspection_report_tableData{}
	data.Rows = make([]Inspection_report_table, 0)
	data.Total = 0
	data.Err = ""

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		data.Err = "连接数据库失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer conn.Close()

	sql = `	
    SELECT
		id,
		datname,schemaname,
		tablename,tabletype,
		tablecomment,tableowner,
		tablespace,reltuples,
		COALESCE(rownum::text,'') AS rownum_show,COALESCE(rownum_deviation::text,'') AS rownum_deviation_show,
		pg_catalog.pg_size_pretty(relationsize) AS show_relationsize,relpages,
		pg_size_pretty(row_of_size) AS row_of_size_show,
		indexnum,pg_catalog.pg_size_pretty(indexsize) AS show_indexsize,
		pg_catalog.pg_size_pretty(tablesize) AS show_tablesize,
		seq_scan,seq_tup_read,
		idx_scan,idx_tup_fetch,
		COALESCE(last_vacuum::TEXT,'') AS last_vacuum,COALESCE(last_autovacuum::TEXT,'') AS last_autovacuum,
		COALESCE(last_analyze::TEXT,'') AS last_analyze,COALESCE(last_autoanalyze::TEXT,'') AS last_autoanalyze
	FROM 
		inspection_report_table
	WHERE
		inspection_report_id=$1
    ` + sql_sort_limit

	rows, err := conn.Query(sql, inspection_report_id)
	if err != nil {
		data.Err = "查询资料失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(
			&rec.Id,
			&rec.Datname, &rec.Schemaname,
			&rec.Tablename, &rec.Tabletype,
			&rec.Tablecomment, &rec.Tableowner,
			&rec.Tablespace, &rec.Reltuples,
			&rec.Rownum, &rec.Rownum_deviation,
			&rec.Relationsize, &rec.Relpages,
			&rec.Row_of_size,
			&rec.Indexnum, &rec.Indexsize,
			&rec.Tablesize,
			&rec.Seq_scan, &rec.Seq_tup_read,
			&rec.Idx_scan, &rec.Idx_tup_fetch,
			&rec.Last_vacuum, &rec.Last_autovacuum,
			&rec.Last_analyze, &rec.Last_autoanalyze)
		if err != nil {
			data.Err = "提取数据失败－－详情：" + err.Error()
			data_chan <- data
			return
		}
		data.Rows = append(data.Rows, rec)
		data.Total = data.Total + 1
	}

	data_chan <- data
	return
}

/*
功能描述：巡检报告－－外部表统计

参数说明：
inspection_report_id  -- 巡检报表－系统编号
row －－ 节点资料

返回值说明：
s -- 通道返回一个Stdout_and_stderr结构体
*/

//定义外部表记录struct
type Inspection_report_foreign_table struct {
	Id           int    `json:"id"`
	Datname      string `json:"datname"`
	Schemaname   string `json:"schemaname"`
	Tablename    string `json:"tablename"`
	Srvname      string `json:"srvname"`
	Srvoptions   string `json:"srvoptions"`
	Ftoptions    string `json:"ftoptions"`
	Tablecomment string `json:"tablecomment"`
	Tableowner   string `json:"tableowner"`
}

//定义列表返回的struct
type Inspection_report_foreign_tableData struct {
	Total int                               `json:"total"`
	Rows  []Inspection_report_foreign_table `json:"rows"`
	Err   string                            `json:"err"`
}

func inspection_report_foreign_table_make(inspection_report_id int, row Row, s chan Stdout_and_stderr) {
	var err error
	var error_msg string
	//定义返回的struct
	var out Stdout_and_stderr
	var rec Inspection_report_foreign_table
	var sql string

	out.Stdout = ""
	out.Stderr = ""
	error_msg = "外部表统计－－"

	//连接pgcluster数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		out.Stderr = error_msg + "连接pgcluster数据库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer conn.Close()

	//连接要统计的节点
	var nodeconn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = row.Host
	config.User = row.Pg_user
	config.Password = row.Pg_password
	config.Database = row.Pg_database
	config.Port = row.Pg_port

	nodeconn, err = pgx.Connect(config)
	if err != nil {
		out.Stderr = error_msg + "连接统计库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer nodeconn.Close()

	sql = `
	SELECT
	    pg_namespace.nspname AS schemaname,
	    pg_class.relname AS tablename,
	    pg_foreign_server.srvname AS srvname,
	    pg_foreign_server.srvoptions::text AS srvoptions,
	    pg_foreign_table.ftoptions::text AS ftoptions,
	    COALESCE(pg_description.description,'') AS tablecomment,
	    pg_authid.rolname AS tableowner
	FROM
	    pg_catalog.pg_foreign_table AS pg_foreign_table 
	    INNER JOIN pg_catalog.pg_class AS pg_class ON pg_class.oid = pg_foreign_table.ftrelid
	    INNER JOIN pg_catalog.pg_authid AS pg_authid ON pg_authid.oid=pg_class.relowner
	    INNER JOIN pg_catalog.pg_namespace AS pg_namespace ON pg_namespace.oid = pg_class.relnamespace
	    INNER JOIN pg_catalog.pg_foreign_server AS pg_foreign_server ON pg_foreign_server.oid = pg_foreign_table.ftserver 
	    LEFT OUTER JOIN pg_catalog.pg_description AS pg_description ON pg_description.objoid=pg_class.oid AND pg_description.objsubid=0
	;
	`
	rows, err := nodeconn.Query(sql)
	if err != nil {
		out.Stderr = error_msg + "查询资料失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(
			&rec.Schemaname, &rec.Tablename,
			&rec.Srvname, &rec.Srvoptions,
			&rec.Ftoptions, &rec.Tablecomment,
			&rec.Tableowner)
		if err != nil {
			out.Stderr = error_msg + "提取数据失败－－详情：" + err.Error()
			s <- out
			return
		}

		sql = `
	    INSERT INTO inspection_report_foreign_table
	    (
	        inspection_report_id,datname,
			schemaname,tablename, 
			srvname,srvoptions,
			ftoptions,tablecomment,
			tableowner
	    )
		VALUES
		(
			$1,$2,
			$3,$4,
			$5,$6,
			$7,$8,
			$9
		) 
	    `
		type Inspection_report_foreign_table struct {
			Id           int    `json:"id"`
			Schemaname   string `json:"schemaname"`
			Tablename    string `json:"tablename"`
			Srvname      string `json:"srvname"`
			Srvoptions   string `json:"srvoptions"`
			Ftoptions    string `json:"ftoptions"`
			Tablecomment string `json:"tablecomment"`
			Tableowner   string `json:"tableowner"`
		}
		_, err = conn.Exec(sql,
			inspection_report_id, row.Pg_database,
			rec.Schemaname, rec.Tablename,
			rec.Srvname, rec.Srvoptions,
			rec.Ftoptions, rec.Tablecomment,
			rec.Tableowner)

		if err != nil {
			out.Stderr = error_msg + "插入数据失败－－详情：" + err.Error()
			s <- out
			return
		}
	}

	out.Stdout = ""
	out.Stderr = ""
	s <- out
	return
}

/*
功能描述：巡检报告－－外部表列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_foreign_table_listHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	var err error
	var sql string
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_foreign_table_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	error_msg = "获取巡检报告－－获取外部表统计信息ID号为[" + r.FormValue("inspection_report_id") + "]－－"

	//判断巡检报告inspection_report_id号合法性
	inspection_report_id, err := strconv.Atoi(r.FormValue("inspection_report_id"))
	if err != nil {
		error_msg = error_msg + "巡检报告id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取数据
	data_chan := make(chan Inspection_report_foreign_tableData)
	go inspection_report_foreign_table_record(inspection_report_id, sql_sort_limit(r), data_chan)

	//异步获取总记录数
	sql = "SELECT COUNT(1) AS num FROM inspection_report_foreign_table WHERE inspection_report_id=" + fmt.Sprintf("%d", inspection_report_id)
	total_chan := make(chan Totalnum)
	go gettotalnum(sql, total_chan)

	//返回异步获取数据结果
	data := <-data_chan
	if data.Err != "" {
		error_msg = error_msg + data.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//返回异步获取总记录数
	total := <-total_chan
	if total.Err == "" {
		data.Total = total.Total
	} else {
		error_msg = error_msg + total.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：获取巡检报告－－外部表统计信息

参数说明：
inspection_report_id   -- 巡检报告的id号
sql_sort_limit         -- 需要分页sql语句

返回值说明：
data_chan -- chan Inspection_report_foreign_tableData
*/

func inspection_report_foreign_table_record(inspection_report_id int, sql_sort_limit string, data_chan chan Inspection_report_foreign_tableData) {
	var err error
	var sql string
	var rec Inspection_report_foreign_table
	var data Inspection_report_foreign_tableData = Inspection_report_foreign_tableData{}
	data.Rows = make([]Inspection_report_foreign_table, 0)
	data.Total = 0
	data.Err = ""

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		data.Err = "连接数据库失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer conn.Close()

	sql = `
    SELECT
		id,datname,
		schemaname,tablename,
		srvname,srvoptions,
		ftoptions,tablecomment,
		tableowner
	FROM 
		inspection_report_foreign_table
	WHERE
		inspection_report_id=$1
    ` + sql_sort_limit

	rows, err := conn.Query(sql, inspection_report_id)
	if err != nil {
		data.Err = "查询资料失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer rows.Close()

	//定义外部表记录struct
	type Inspection_report_foreign_table struct {
		Id           int    `json:"id"`
		Datname      string `json:"datname"`
		Schemaname   string `json:"schemaname"`
		Tablename    string `json:"tablename"`
		Srvname      string `json:"srvname"`
		Srvoptions   string `json:"srvoptions"`
		Ftoptions    string `json:"ftoptions"`
		Tablecomment string `json:"tablecomment"`
		Tableowner   string `json:"tableowner"`
	}
	for rows.Next() {
		err = rows.Scan(
			&rec.Id, &rec.Datname,
			&rec.Schemaname, &rec.Tablename,
			&rec.Srvname, &rec.Srvoptions,
			&rec.Ftoptions, &rec.Tablecomment,
			&rec.Tableowner)
		if err != nil {
			data.Err = "提取数据失败－－详情：" + err.Error()
			data_chan <- data
			return
		}
		data.Rows = append(data.Rows, rec)
		data.Total = data.Total + 1
	}

	data_chan <- data
	return
}

/*
功能描述：巡检报告－－索引统计

参数说明：
inspection_report_id  -- 巡检报表－系统编号
count_system_obj --控制是否统计系统对象--值分别是 “统计”，“不统计”
row －－ 节点资料
dattablespace --数据库默认表空间

返回值说明：
s -- 通道返回一个Stdout_and_stderr结构体
*/

//定义数据表记录struct

type Inspection_report_index struct {
	Id           int    `json:"id"`
	Datname      string `json:"datname"`
	Schemaname   string `json:"schemaname"`
	Tablename    string `json:"tablename"`
	Indexname    string `json:"indexname"`
	Indexcomment string `json:"indexcomment"`
	Indexowner   string `json:"indexowner"`
	Uniqueindex  string `json:"uniqueindex"`
	Indexsize    string `json:"indexsize"`
	Tablespace   string `json:"tablespace"`
	Idx_scan     int64  `json:"idx_scan"`
	Indexdef     string `json:"indexdef"`
}

//定义列表返回的struct
type Inspection_report_indexData struct {
	Total int                       `json:"total"`
	Rows  []Inspection_report_index `json:"rows"`
	Err   string                    `json:"err"`
}

func inspection_report_index_make(inspection_report_id int, count_system_obj string, row Row, s chan Stdout_and_stderr) {
	var err error
	var error_msg string

	//定义返回的struct
	var out Stdout_and_stderr
	out.Stdout = ""
	out.Stderr = ""

	var rec Inspection_report_index
	var sql string

	error_msg = "索引统计－－统计库为[" + row.Pg_database + "]－－"

	//连接pgcluster数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		out.Stderr = error_msg + "连接pgcluster数据库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer conn.Close()

	//连接要统计的节点
	var nodeconn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = row.Host
	config.User = row.Pg_user
	config.Password = row.Pg_password
	config.Database = row.Pg_database
	config.Port = row.Pg_port

	nodeconn, err = pgx.Connect(config)
	if err != nil {
		out.Stderr = error_msg + "连接统计库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer nodeconn.Close()

	//获取数据库默认表空间
	sql = `
	SELECT
		pg_tablespace.spcname AS dattablespace
	FROM
		pg_catalog.pg_database AS pg_database 
		INNER JOIN pg_catalog.pg_tablespace AS pg_tablespace ON pg_tablespace.oid=pg_database.dattablespace
	WHERE
		pg_database.datname=$1
	`
	rows, err := nodeconn.Query(sql, row.Pg_database)
	if err != nil {
		out.Stderr = error_msg + "查询数据库默认表空间失败－－详情：" + err.Error()
		s <- out
		return
	}
	var dattablespace string
	if rows.Next() {
		err = rows.Scan(&dattablespace)
		if err != nil {
			out.Stderr = error_msg + "获取数据库默认表空间数据失败－－详情：" + err.Error()
			s <- out
			return
		}
	}
	rows.Close()

	where := " "
	if count_system_obj == "不统计" {
		where = where + " AND pg_namespace.nspname NOT IN ('pg_catalog','information_schema')"
	}

	sql = `
	SELECT
		pg_namespace.nspname AS schemaname ,tablename.relname AS tablename,
		pg_class.relname AS indexname,COALESCE(pg_description.description,'') AS inexcomment,
		pg_authid.rolname AS indexowner,CASE WHEN pg_index.indisunique THEN '是' ELSE '否' END AS indisunique,
		pg_catalog.pg_table_size(pg_class.oid)::text AS indexsize,COALESCE(pg_tablespace.spcname,'` + dattablespace + `') AS tablespace,
		COALESCE(pg_stat_all_indexes.idx_scan,0) AS idx_scan,pg_catalog.pg_get_indexdef(pg_class.oid) AS indexdef
	FROM
		pg_catalog.pg_class AS pg_class
		INNER JOIN pg_catalog.pg_namespace AS pg_namespace ON pg_namespace.oid=pg_class.relnamespace
		INNER JOIN pg_catalog.pg_index AS pg_index ON pg_index.indexrelid=pg_class.oid
		INNER JOIN pg_catalog.pg_class AS tablename ON tablename.oid=pg_index.indrelid
		LEFT OUTER JOIN pg_catalog.pg_description AS pg_description ON pg_description.objoid=pg_class.oid AND pg_description.objsubid=0
		LEFT OUTER JOIN (
		    SELECT 
			    pg_class.oid 
			FROM 
			    pg_catalog.pg_class AS pg_class
				INNER JOIN pg_catalog.pg_namespace AS pg_namespace ON pg_class.relnamespace=pg_namespace.oid  
			WHERE
				pg_class.relname='pg_class' 
				AND pg_namespace.nspname='pg_catalog' 
		) AS classoid ON classoid.oid=pg_description.classoid
		INNER JOIN pg_catalog.pg_authid AS pg_authid ON pg_authid.oid=pg_class.relowner
		LEFT OUTER JOIN pg_catalog.pg_tablespace AS pg_tablespace ON pg_tablespace.oid=pg_class.reltablespace
		LEFT OUTER JOIN pg_catalog.pg_stat_all_indexes AS pg_stat_all_indexes ON pg_stat_all_indexes.indexrelid=pg_class.oid
	WHERE
		pg_class.relkind='i'
		AND pg_namespace.nspname != 'pg_toast'
		` + where + `
	`

	rows, err = nodeconn.Query(sql)
	if err != nil {
		out.Stderr = error_msg + "查询数据失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(
			&rec.Schemaname, &rec.Tablename,
			&rec.Indexname, &rec.Indexcomment,
			&rec.Indexowner, &rec.Uniqueindex,
			&rec.Indexsize, &rec.Tablespace,
			&rec.Idx_scan, &rec.Indexdef)
		if err != nil {
			out.Stderr = error_msg + "提取数据失败－－详情：" + err.Error()
			s <- out
			return
		}

		sql = `
	    INSERT INTO inspection_report_index
	    (
	        inspection_report_id,datname,
			schemaname,tablename,
			indexname,indexcomment,
			indexowner,uniqueindex,
			indexsize,tablespace,
			idx_scan,indexdef
	    )
		VALUES
		(
			$1,$2,
			$3,$4,
			$5,$6,
			$7,$8,
			$9,$10,
			$11,$12
		) 
	    `
		_, err = conn.Exec(sql,
			inspection_report_id, row.Pg_database,
			rec.Schemaname, rec.Tablename,
			rec.Indexname, rec.Indexcomment,
			rec.Indexowner, rec.Uniqueindex,
			rec.Indexsize, rec.Tablespace,
			rec.Idx_scan, rec.Indexdef)

		if err != nil {
			out.Stderr = error_msg + "插入数据失败－－详情：" + err.Error()
			s <- out
			return
		}

	}

	out.Stdout = ""
	out.Stderr = ""
	s <- out
	return
}

/*
功能描述：巡检报告－－索引列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_index_listHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	var err error
	var sql string
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_index_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}

	error_msg = "获取巡检报告－－获取索引统计信息ID号为[" + r.FormValue("inspection_report_id") + "]－－"

	//判断巡检报告inspection_report_id号合法性
	inspection_report_id, err := strconv.Atoi(r.FormValue("inspection_report_id"))
	if err != nil {
		error_msg = error_msg + "巡检报告id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取数据
	data_chan := make(chan Inspection_report_indexData)
	go inspection_report_index_record(inspection_report_id, sql_sort_limit(r), data_chan)

	//异步获取总记录数
	sql = "SELECT COUNT(1) AS num FROM inspection_report_index WHERE inspection_report_id=" + fmt.Sprintf("%d", inspection_report_id)
	total_chan := make(chan Totalnum)
	go gettotalnum(sql, total_chan)

	//返回异步获取数据结果
	data := <-data_chan
	if data.Err != "" {
		error_msg = error_msg + data.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//返回异步获取总记录数
	total := <-total_chan
	if total.Err == "" {
		data.Total = total.Total
	} else {
		error_msg = error_msg + total.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：获取巡检报告－－索引统计信息

参数说明：
inspection_report_id   -- 巡检报告的id号
sql_sort_limit         -- 需要分页sql语句

返回值说明：
data_chan -- chan Inspection_report_indexData
*/

func inspection_report_index_record(inspection_report_id int, sql_sort_limit string, data_chan chan Inspection_report_indexData) {
	var err error
	var sql string
	var rec Inspection_report_index
	var data Inspection_report_indexData = Inspection_report_indexData{}
	data.Rows = make([]Inspection_report_index, 0)
	data.Total = 0
	data.Err = ""

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		data.Err = "连接数据库失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer conn.Close()

	sql = `
    SELECT
		id,
		datname,schemaname,
		tablename,indexname,
		indexcomment,indexowner,
		uniqueindex,pg_catalog.pg_size_pretty(indexsize) AS show_indexsize,
		tablespace,idx_scan,
		indexdef
	FROM 
		inspection_report_index
	WHERE
		inspection_report_id=$1
    ` + sql_sort_limit

	rows, err := conn.Query(sql, inspection_report_id)
	if err != nil {
		data.Err = "查询资料失败－－详情：" + err.Error()
		data_chan <- data
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(
			&rec.Id,
			&rec.Datname, &rec.Schemaname,
			&rec.Tablename, &rec.Indexname,
			&rec.Indexcomment, &rec.Indexowner,
			&rec.Uniqueindex, &rec.Indexsize,
			&rec.Tablespace, &rec.Idx_scan,
			&rec.Indexdef)
		if err != nil {
			data.Err = "提取数据失败－－详情：" + err.Error()
			data_chan <- data
			return
		}
		data.Rows = append(data.Rows, rec)
		data.Total = data.Total + 1
	}

	data_chan <- data
	return
}

/*
功能描述：修改巡检报告名称

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_updateHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	var err error
	var sql string
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_updateHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "修改巡检报告名称－－ID号为 [ " + r.FormValue("inspection_report_id") + " ]－－"

	//判断巡检报告inspection_report_id号合法性
	inspection_report_id, err := strconv.Atoi(r.FormValue("inspection_report_id"))
	if err != nil {
		error_msg = error_msg + "巡检报告ID号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	if r.FormValue("report_name") == "" {
		error_msg = error_msg + "巡检报告名称不能为空"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		error_msg = error_msg + "连接db失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql = "UPDATE inspection_report SET report_name=$1 WHERE id=$2"
	_, err = conn.Exec(sql, r.FormValue("report_name"), inspection_report_id)
	if err != nil {
		error_msg = error_msg + "更新数据出错，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	OutputJson(w, "SUCCESS", "修改资料保存成功", 0)
	go write_log(remote_ip, modlename, username, "Log", error_msg+"修改资料成功")
	return

}

/*
功能描述：删除巡检报告

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_deleteHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	var err error
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_deleteHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "删除巡检报告－－ID号为 [ " + r.FormValue("inspection_report_id") + " ]－－"

	//判断巡检报告inspection_report_id号合法性
	inspection_report_id, err := strconv.Atoi(r.FormValue("inspection_report_id"))
	if err != nil {
		error_msg = error_msg + "巡检报告ID号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	end := make(chan Stdout_and_stderr)
	go inspection_report_delete(inspection_report_id, end)
	t := <-end
	if t.Stderr != "" {
		error_msg = error_msg + t.Stderr
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	OutputJson(w, "SUCCESS", "删除记录成功", 0)
	go write_log(remote_ip, modlename, username, "Log", error_msg+"删除记录成功")
	return

}

func inspection_report_delete(inspection_report_id int, s chan Stdout_and_stderr) {
	var err error
	var sql string
	//定义返回的struct
	var out Stdout_and_stderr
	out.Stdout = ""
	out.Stderr = ""

	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		out.Stderr = "连接数据库失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer conn.Close()

	sql = `
	DELETE FROM inspection_report WHERE id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	DELETE FROM inspection_report_state WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	DELETE FROM inspection_report_tablespace WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	DELETE FROM inspection_report_role WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	DELETE FROM inspection_report_database WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	DELETE FROM inspection_report_table WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	DELETE FROM inspection_report_foreign_table WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	DELETE FROM inspection_report_index WHERE inspection_report_id=` + fmt.Sprintf("%d", inspection_report_id) + `;
	`
	_, err = conn.Exec(sql)
	if err != nil {
		out.Stderr = "删除记录失败－－详情：" + err.Error()
		s <- out
		return
	}

	out.Stdout = "删除记录成功"
	s <- out
	return
}

/*
功能描述：巡检报告导出接口

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func inspection_report_exportHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	var err error
	var title []string
	remote_ip := get_remote_ip(r)
	modlename := "inspection_report_exportHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "巡检报告导出－－ID号为 [ " + r.FormValue("inspection_report_id") + " ]－－"

	//判断巡检报告inspection_report_id号合法性
	inspection_report_id, err := strconv.Atoi(r.FormValue("inspection_report_id"))
	if err != nil {
		error_msg = error_msg + "巡检报告ID号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//异步获取状态统计数据
	state_chan := make(chan Inspection_report_stateData)
	go inspection_report_state_record(inspection_report_id, "", state_chan)

	//异步获取表空间统计数据
	tablespace_chan := make(chan Inspection_report_tablespaceData)
	go inspection_report_tablespace_record(inspection_report_id, "", tablespace_chan)

	//异步获取角色统计数据
	role_chan := make(chan Inspection_report_roleData)
	go inspection_report_role_record(inspection_report_id, "", role_chan)

	//异步获取角色统计数据
	database_chan := make(chan Inspection_report_databaseData)
	go inspection_report_database_record(inspection_report_id, "", database_chan)

	//异步获取数据表统计数据
	table_chan := make(chan Inspection_report_tableData)
	go inspection_report_table_record(inspection_report_id, "", table_chan)

	//异步获取外部表统计数据
	foreign_table_chan := make(chan Inspection_report_foreign_tableData)
	go inspection_report_foreign_table_record(inspection_report_id, "", foreign_table_chan)

	//异步获取索引统计数据
	index_chan := make(chan Inspection_report_indexData)
	go inspection_report_index_record(inspection_report_id, "", index_chan)

	//开始写入excel文件
	var file *xlsx.File
	var sheet *xlsx.Sheet
	var row *xlsx.Row
	var cell *xlsx.Cell
	//定义标题单元格式
	titlestyle := xlsx.NewStyle()
	fill := *xlsx.NewFill("solid", "0092D050", "00000000")
	font := *xlsx.NewFont(12, "Verdana")
	border := *xlsx.NewBorder("thin", "thin", "thin", "thin")
	titlestyle.Fill = fill
	titlestyle.Font = font
	titlestyle.Border = border

	//定义内容格式
	contentstyle := xlsx.NewStyle()
	fill = *xlsx.NewFill("solid", "00FFFFFF", "00000000")
	font = *xlsx.NewFont(10, "Verdana")
	border = *xlsx.NewBorder("thin", "thin", "thin", "thin")
	contentstyle.Fill = fill
	contentstyle.Font = font
	contentstyle.Border = border

	file = xlsx.NewFile()
	//写入状态统计值
	sheet, err = file.AddSheet("状态统计")
	if err != nil {
		error_msg = error_msg + "增加“状态统计”Sheet出错－－详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	//写入标题
	title = []string{"ID号", "项目", "值"}
	row = sheet.AddRow()
	for _, v := range title {
		cell = row.AddCell()
		cell.Value = v
		cell.SetStyle(titlestyle)
	}

	//获取状态统计数据
	data_state := <-state_chan
	if data_state.Err != "" {
		error_msg = data_state.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	for _, v := range data_state.Rows {
		rec := reflect.ValueOf(v)
		row = sheet.AddRow()
		for k, _ := range title {
			cell = row.AddCell()
			cell.SetValue(rec.Field(k).Interface())
			cell.SetStyle(contentstyle)
		}
	}

	//写入表空间统计值
	sheet, err = file.AddSheet("表空间")
	if err != nil {
		error_msg = error_msg + "增加“表空间”Sheet出错－－详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	//写入标题
	title = []string{"ID号", "表空间名称", "注释", "所有者", "路径", "占用空间", "数据表数", "索引数"}
	row = sheet.AddRow()
	for _, v := range title {
		cell = row.AddCell()
		cell.Value = v
		cell.SetStyle(titlestyle)
	}

	//获取表空间统计数据
	data_tablespace := <-tablespace_chan
	if data_tablespace.Err != "" {
		error_msg = error_msg + data_tablespace.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	for _, v := range data_tablespace.Rows {
		rec := reflect.ValueOf(v)
		row = sheet.AddRow()
		for k, _ := range title {
			cell = row.AddCell()
			cell.SetValue(rec.Field(k).Interface())
			cell.SetStyle(contentstyle)
		}
	}

	//写入角色统计值
	sheet, err = file.AddSheet("角色")
	if err != nil {
		error_msg = error_msg + "增加“角色”Sheet出错－－详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//写入标题
	title = []string{"ID号", "用户名", "注释", "超级用户", "准许创建用户", "准许创建数据库", "准许登录", "复制角色", "并发连接数", "口令状态", "口令过期时间", "数据库数", "数据表数", "索引数"}
	row = sheet.AddRow()
	for _, v := range title {
		cell = row.AddCell()
		cell.Value = v
		cell.SetStyle(titlestyle)
	}

	//获取角色统计数据
	data_role := <-role_chan
	if data_role.Err != "" {
		error_msg = error_msg + data_role.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	for _, v := range data_role.Rows {
		rec := reflect.ValueOf(v)
		row = sheet.AddRow()
		for k, _ := range title {
			cell = row.AddCell()
			cell.SetValue(rec.Field(k).Interface())
			cell.SetStyle(contentstyle)
		}
	}

	//写入数据库统计值
	sheet, err = file.AddSheet("数据库")
	if err != nil {
		error_msg = error_msg + "增加“数据库”Sheet出错－－详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//写入标题
	title = []string{"ID号", "数据库名称", "注释", "所有者", "默认编码", "排序规则", "分组规则", "模板数据库", "准许连接", "最大连接数", "默认表空间", "占用空间", "数据表数", "索引数"}
	row = sheet.AddRow()
	for _, v := range title {
		cell = row.AddCell()
		cell.Value = v
		cell.SetStyle(titlestyle)
	}

	//获取数据库统计数据
	data_database := <-database_chan
	if data_database.Err != "" {
		error_msg = error_msg + data_database.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	for _, v := range data_database.Rows {
		rec := reflect.ValueOf(v)
		row = sheet.AddRow()
		for k, _ := range title {
			cell = row.AddCell()
			cell.SetValue(rec.Field(k).Interface())
			cell.SetStyle(contentstyle)
		}
	}

	//写入数据表统计值
	sheet, err = file.AddSheet("数据表")
	if err != nil {
		error_msg = error_msg + "增加“数据表”Sheet出错－－详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	//写入标题
	title = []string{"ID号", "数据库名称", "所属模式", "表名", "表类型", "注释", "所有者", "存储表空间", "记录数（估值）", "记录数", "记录数偏差", "表文件占用空间", "占用盘页（估值）", "每行占用空间", "索引数", "索引文件占用空间", "表相关文件占用空间", "顺序扫描次数", "顺序扫描取得行数", "索引扫描次数", "索引扫描取得行数", "手动清理时间", "自动清理时间", "手动分析时间", "自动分析时间"}
	row = sheet.AddRow()
	for _, v := range title {
		cell = row.AddCell()
		cell.Value = v
		cell.SetStyle(titlestyle)
	}

	//获取数据表统计数据
	data_table := <-table_chan
	if data_table.Err != "" {
		error_msg = error_msg + data_table.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	for _, v := range data_table.Rows {
		rec := reflect.ValueOf(v)
		row = sheet.AddRow()
		for k, _ := range title {
			cell = row.AddCell()
			cell.SetValue(rec.Field(k).Interface())
			cell.SetStyle(contentstyle)
		}
	}

	//写入外部表统计值
	sheet, err = file.AddSheet("外部表")
	if err != nil {
		error_msg = error_msg + "增加“外部表”Sheet出错－－详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	//写入标题
	title = []string{"ID号", "数据库名称", "所属模式", "表名", "外部服务器名称", "外部服务器配置", "外部表名称", "注释", "所有者"}
	row = sheet.AddRow()
	for _, v := range title {
		cell = row.AddCell()
		cell.Value = v
		cell.SetStyle(titlestyle)
	}

	//获取外部表统计数据
	data_foreign_table := <-foreign_table_chan
	if data_foreign_table.Err != "" {
		error_msg = error_msg + data_foreign_table.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	for _, v := range data_foreign_table.Rows {
		rec := reflect.ValueOf(v)
		row = sheet.AddRow()
		for k, _ := range title {
			cell = row.AddCell()
			cell.SetValue(rec.Field(k).Interface())
			cell.SetStyle(contentstyle)
		}
	}

	//写入索引统计值
	sheet, err = file.AddSheet("索引")
	if err != nil {
		error_msg = error_msg + "增加“索引”Sheet出错－－详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//写入标题
	title = []string{"ID号", "数据库名", "所属模式", "表名", "索引名", "注释", "所有者", "唯一索引", "占用空间", "存储表空间", "索引扫描次数", "索引定义"}
	row = sheet.AddRow()
	for _, v := range title {
		cell = row.AddCell()
		cell.Value = v
		cell.SetStyle(titlestyle)
	}

	//获取索引统计数据
	data_index := <-index_chan
	if data_index.Err != "" {
		error_msg = error_msg + data_index.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	for _, v := range data_index.Rows {
		rec := reflect.ValueOf(v)
		row = sheet.AddRow()
		for k, _ := range title {
			cell = row.AddCell()
			cell.SetValue(rec.Field(k).Interface())
			cell.SetStyle(contentstyle)
		}
	}

	//保存文件
	filename := "inspection_report_" + username + ".xlsx"
	err = file.Save("./easyui/inspection_report/" + filename)
	if err != nil {
		error_msg = error_msg + "保存Excel出错－－详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//操作服务(启动，重启和关闭)结果信息json结构
	type Result_report_export struct {
		Return_code       string `json:"return_code"`
		Return_msg        string `json:"return_msg"`
		Show_login_dialog int    `json:"show_login_dialog"`
		Url               string `json:"url"`
		Filename          string `json:"filename"`
	}

	error_msg = "生成巡检报告成功"
	out := &Result_report_export{"SUCCESS", error_msg, 0, "/inspection_report/" + filename, filename}
	b, _ := json.Marshal(out)
	w.Write(b)
	go write_log(remote_ip, modlename, username, "Log", error_msg)
	return

	//download_file(w, r, filename)

}

/*
功能描述：下载文件

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针
filename --要下载文件的名称

返回值说明：无
*/

func download_file(w http.ResponseWriter, r *http.Request, filename string) {
	path := "./easyui/inspection_report/" + filename
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Cache-Control", "must-revalidate, post-check=0, pre-check=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	http.ServeFile(w, r, path)
}

/*
功能描述：获取某个查询得到的记录数

参数说明：
sql -- 要执行的sql语句
s   -- chan Totalnum

返回值说明：
Totalnum结构
*/

type Totalnum struct {
	Total int    `json:"total"`
	Err   string `json:"err"`
}

func gettotalnum(sql string, s chan Totalnum) {
	//定义返回的struct
	var err error
	var error_msg string
	var out Totalnum
	out.Total = 0
	out.Err = ""
	error_msg = "获取某个查询得到的记录数－－"
	//连接数据库
	var conn *pgx.Conn
	conn, err = pgx.Connect(extractConfig())
	if err != nil {
		out.Err = error_msg + "连接db失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer conn.Close()

	//统计总记录数
	rows, err := conn.Query(sql)
	if err != nil {
		out.Err = error_msg + "执行查询失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer rows.Close()
	if rows.Next() {
		err = rows.Scan(&out.Total)
		if err != nil {
			out.Err = error_msg + "提取数据失败－－详情：" + err.Error()
			s <- out
			return
		}
	}
	s <- out
	return
}

/*
功能描述：获取某个节点某个查询得到的记录数

参数说明：
sql -- 要执行的sql语句
s   -- chan Totalnum

返回值说明：
Totalnum结构
*/

func getnode_totalnum(nodeid int, sql string, s chan Totalnum) {
	//定义返回的struct
	var err error
	var error_msg string
	var out Totalnum
	out.Total = 0
	out.Err = ""
	error_msg = "获取某个查询得到的记录数－－"
	//获取节点资料
	row_chan := make(chan Row)
	go get_node_row(nodeid, row_chan)
	noderow := <-row_chan
	if noderow.Return_code == "FAIL" {
		out.Err = error_msg + "获取节点资料失败,详情：" + noderow.Return_msg
		s <- out
		return
	}

	//连接数据库
	var conn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = noderow.Host
	config.User = noderow.Pg_user
	config.Password = noderow.Pg_password
	config.Database = noderow.Pg_database
	config.Port = noderow.Pg_port
	conn, err = pgx.Connect(config)
	if err != nil {
		out.Err = error_msg + "连接数据库失败，详情：" + err.Error()
		s <- out
		return
	}
	defer conn.Close()

	//统计总记录数
	rows, err := conn.Query(sql)
	if err != nil {
		out.Err = error_msg + "执行查询失败－－详情：" + err.Error()
		s <- out
		return
	}
	defer rows.Close()
	if rows.Next() {
		err = rows.Scan(&out.Total)
		if err != nil {
			out.Err = error_msg + "提取数据失败－－详情：" + err.Error()
			s <- out
			return
		}
	}
	s <- out
	return
}

/*
功能描述：获取某个节点ip绑定情况

参数说明：
nodeid   -- 节点的id号

返回值说明：
s -- 通道返回一个Stdout_and_stderr结构体
*/

func get_node_ip_bind_status(nodeid int, s chan Stdout_and_stderr) {
	//定义返回的struct
	var out Stdout_and_stderr

	row_chan := make(chan Row)
	go get_node_row(nodeid, row_chan)
	row := <-row_chan
	if row.Return_code == "FAIL" {
		out.Stdout = ""
		out.Stderr = "获取节点资料失败,详情：" + row.Return_msg
		s <- out
		return
	}
	//获取ip绑定情况,如果运行提示找不到ip这个命令，则在登录的主机上把ip这个命令软连接到/usr/bin目录下即可，ln -s /sbin/ip /usr/bin/ip
	cmd := "cmdpath=`which 'ip'`;$cmdpath a"
	//stdout, stderr := ssh_run(row.Bind_vip_authmethod, "root", row.Bind_vip_user, row.Bind_vip_password, row.Host, row.Ssh_port, cmd)
	stdout, stderr := ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
	out.Stdout = stdout
	out.Stderr = stderr
	if stderr != "" && row.Bind_vip_user != "" {
		stdout, stderr := ssh_run(row.Bind_vip_authmethod, "root", row.Bind_vip_user, row.Bind_vip_password, row.Host, row.Ssh_port, cmd)
		out.Stdout = stdout
		out.Stderr = stderr
	}
	s <- out
	return
}

/*
功能描述：获取某个节点配置资料

参数说明：
nodeid   -- 节点的id号

返回值说明：
s -- 通道返回一个Row结构体, Return_code = FAIL表示获取数据失败,失败原因存入在Return_msg中,
*/

func get_node_row(nodeid int, s chan Row) {
	//连接数据库
	var row Row
	row.Return_code = "SUCCESS"
	row.Return_msg = ""
	var conn *pgx.Conn
	conn, err := pgx.Connect(extractConfig())
	if err != nil {
		row.Return_code = "FAIL"
		row.Return_msg = "连接数据库失败，详情：" + err.Error()
		s <- row
		return
	}
	defer conn.Close()

	//查询返回节点信息
	sql := `
    SELECT 
        id,node_name,
        createtime::text,host,
		ssh_authmethod,
        ssh_port,ssh_user,
        ssh_password,pg_bin,
        pg_data,pg_log,
		pg_port,pg_database,
		pg_user,pg_password,
        master_vip,master_vip_networkcard,
        slave_vip,slave_vip_networkcard,   
		bind_vip_authmethod, 
        bind_vip_user,bind_vip_password,     
        remark 
    FROM 
        nodes 
    WHERE 
        id = $1 
    `

	rows, err := conn.Query(sql, nodeid)
	if err != nil {
		row.Return_code = "FAIL"
		row.Return_msg = "执行查询失败，详情：" + err.Error()
		s <- row
		return
	}

	if rows.Next() {
		err = rows.Scan(
			&row.Id, &row.Node_name,
			&row.Createtime, &row.Host,
			&row.Ssh_authmethod,
			&row.Ssh_port, &row.Ssh_user,
			&row.Ssh_password, &row.Pg_bin,
			&row.Pg_data, &row.Pg_log,
			&row.Pg_port, &row.Pg_database,
			&row.Pg_user, &row.Pg_password,
			&row.Master_vip, &row.Master_vip_networkcard,
			&row.Slave_vip, &row.Slave_vip_networkcard,
			&row.Bind_vip_authmethod,
			&row.Bind_vip_user, &row.Bind_vip_password,
			&row.Remark)
		if err != nil {
			row.Return_code = "FAIL"
			row.Return_msg = "执行查询失败，详情：" + err.Error()
			s <- row
			return
		}
	}
	rows.Close()
	s <- row
	return
}

/*
功能描述：获取数据库列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func get_database_listHandler(w http.ResponseWriter, r *http.Request) {
	//节点行信息json结构
	type List struct {
		Datname string `json:"datname"`
		Dattext string `json:"dattext"`
	}

	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "get_database_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "获取数据库列表－－节点ID号为[" + r.FormValue("id") + "]－－"

	//判断节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = error_msg + "节点id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	noderow := <-row_chan
	if noderow.Return_code == "FAIL" {
		error_msg = error_msg + "获取节点资料失败－－详情：" + noderow.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = noderow.Host
	config.User = noderow.Pg_user
	config.Password = noderow.Pg_password
	config.Database = noderow.Pg_database
	config.Port = noderow.Pg_port
	conn, err = pgx.Connect(config)
	if err != nil {
		error_msg = error_msg + "连接数据库失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql := ""
	var rows *pgx.Rows

	sql = `
	SELECT
		pg_database.datname,pg_database.datname||case when pg_shdescription.description IS not null then '－－'||pg_shdescription.description else '' end AS dattext
	FROM
		pg_catalog.pg_database AS pg_database 
		LEFT OUTER JOIN pg_catalog.pg_shdescription AS pg_shdescription ON pg_shdescription.objoid=pg_database.oid
	WHERE
	    pg_database.datallowconn
	ORDER BY
		pg_database.datname
	`
	rows, err = conn.Query(sql)
	defer rows.Close()

	if err != nil {
		error_msg = error_msg + "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	var Rows []List
	Rows = make([]List, 0)

	for rows.Next() {
		var row List
		err = rows.Scan(&row.Datname, &row.Dattext)
		if err != nil {
			error_msg = error_msg + "执行查询失败，详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		Rows = append(Rows, row)
	}
	ret, _ := json.Marshal(Rows)
	w.Write(ret)
}

/*
功能描述：管理工具－－进程管理－－获取某个数据库或所有数据库的进程列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func processadmin_process_listHandler(w http.ResponseWriter, r *http.Request) {
	//节点行信息json结构
	type List struct {
		Pid                    int64  `json:"pid"`
		Datname                string `json:"datname"`
		Client_addr            string `json:"client_addr"`
		Usename                string `json:"usename"`
		Application_name       string `json:"application_name"`
		Backend_start          string `json:"backend_start"`
		Backend_continued_time string `json:"backend_continued_time"`
		Xact_start             string `json:"xact_start"`
		Xact_continued_time    string `json:"xact_continued_time"`
		Query_start            string `json:"query_start"`
		Query_continued_time   string `json:"query_continued_time"`
		Wait_event_type        string `json:"wait_event_type"`
		Wait_event             string `json:"wait_event"`
		State                  string `json:"state"`
		Backend_xid            string `json:"backend_xid"`
		Query                  string `json:"query"`
	}

	//定义列表返回的struct
	type ListData struct {
		Total int    `json:"total"`
		Rows  []List `json:"rows"`
	}

	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "processadmin_process_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "管理工具－－进程管理－－获取某个数据库或所有数据库的进程列表－－节点ID号为[" + r.FormValue("id") + "]－－数据库datname为[" + r.FormValue("datname") + "]－－"

	//判断节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = error_msg + "节点id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	noderow := <-row_chan
	if noderow.Return_code == "FAIL" {
		error_msg = error_msg + "获取节点资料失败－－详情：" + noderow.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = noderow.Host
	config.User = noderow.Pg_user
	config.Password = noderow.Pg_password
	config.Database = noderow.Pg_database
	config.Port = noderow.Pg_port
	conn, err = pgx.Connect(config)
	if err != nil {
		error_msg = error_msg + "连接数据库失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql := ""
	var rows *pgx.Rows

	where := ""
	if r.FormValue("datname") != "" {
		where = " WHERE pg_stat_activity.datname='" + sql_data_encode(r.FormValue("datname")) + "' "
	}

	sql = `
	SELECT
		pg_stat_activity.pid::bigint,
		pg_stat_activity.datname,
		pg_stat_activity.client_addr::text,
		pg_stat_activity.usename,
		pg_stat_activity.application_name,
		pg_stat_activity.backend_start::timestamp(0)::text,
		(now()::timestamp(0)-pg_stat_activity.backend_start::timestamp(0))::text AS backend_continued_time,
		COALESCE(pg_stat_activity.xact_start::timestamp(0)::text,'') AS xact_start,
		COALESCE((now()::timestamp(0)-pg_stat_activity.xact_start::timestamp(0))::text,'') AS xact_continued_time,
		COALESCE(pg_stat_activity.query_start::timestamp(0)::text,'') AS query_start,
		COALESCE((now()::timestamp(0)-pg_stat_activity.query_start::timestamp(0))::text,'') AS query_continued_time,
		COALESCE(pg_stat_activity.wait_event_type,'') AS wait_event_type ,
		COALESCE(pg_stat_activity.wait_event,'') AS wait_event,
		pg_stat_activity.state,
		COALESCE(pg_stat_activity.backend_xid::text,'') AS backend_xid,
		pg_stat_activity.query
	FROM
		pg_catalog.pg_stat_activity AS pg_stat_activity 
	` + where + sql_sort_limit(r)

	rows, err = conn.Query(sql)
	defer rows.Close()

	if err != nil {
		error_msg = error_msg + "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	var data ListData = ListData{}
	data.Rows = make([]List, 0)
	data.Total = 0

	for rows.Next() {
		var row List
		err = rows.Scan(
			&row.Pid,
			&row.Datname,
			&row.Client_addr,
			&row.Usename,
			&row.Application_name,
			&row.Backend_start,
			&row.Backend_continued_time,
			&row.Xact_start,
			&row.Xact_continued_time,
			&row.Query_start,
			&row.Query_continued_time,
			&row.Wait_event_type,
			&row.Wait_event,
			&row.State,
			&row.Backend_xid,
			&row.Query)
		if err != nil {
			error_msg = error_msg + "执行查询失败，详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		data.Rows = append(data.Rows, row)
	}
	data.Total = len(data.Rows)
	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：管理工具－－进程管理－－取消查询

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func processadmin_cancelqueryHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "processadmin_cancelqueryHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "管理工具－－进程管理－－取消查询－－节点ID号为[" + r.FormValue("id") + "]－－要取消查询的pid为[" + r.FormValue("pid") + "]－－"

	ret_code, ret_result := precess_cancelquery(r.FormValue("id"), r.FormValue("pid"))
	if ret_code == "FAIL" {
		error_msg = error_msg + ret_result
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	} else {
		logcontent := error_msg + ret_result
		OutputJson(w, "SUCCESS", "执行成功！", 0)
		go write_log(remote_ip, modlename, username, "Log", logcontent)
		return
	}
}

/*
功能描述：管理工具－－进程管理－－杀死进程

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func processadmin_killprocessHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "processadmin_killprocessHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "管理工具－－进程管理－－杀死进程－－节点ID号为[" + r.FormValue("id") + "]－－要杀死的pid为[" + r.FormValue("pid") + "]－－"

	ret_code, ret_result := precess_killprecess(r.FormValue("id"), r.FormValue("pid"))
	if ret_code == "FAIL" {
		error_msg = error_msg + ret_result
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	} else {
		logcontent := error_msg + ret_result
		OutputJson(w, "SUCCESS", "执行成功！", 0)
		go write_log(remote_ip, modlename, username, "Log", logcontent)
		return
	}
}

/*
功能描述：管理工具－－进程管理－－获取某个数据库或所有数据库的受阻塞锁列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func lockadmin_lock_listHandler(w http.ResponseWriter, r *http.Request) {
	//节点行信息json结构
	type List struct {
		Locktype               string `json:"locktype"`
		Pid                    int64  `json:"pid"`
		Mode                   string `json:"mode"`
		Mode_level             int32  `json:"mode_level"`
		Granted                string `json:"granted"`
		Datname                string `json:"datname"`
		Nspname                string `json:"nspname"`
		Relname                string `json:"relname"`
		Relkind                string `json:"relkind"`
		Page                   string `json:"page"`
		Tuple                  string `json:"tuple"`
		Transactionid          string `json:"transactionid"`
		Client_addr            string `json:"client_addr"`
		Usename                string `json:"usename"`
		Application_name       string `json:"application_name"`
		Backend_start          string `json:"backend_start"`
		Backend_continued_time string `json:"backend_continued_time"`
		Xact_start             string `json:"xact_start"`
		Xact_continued_time    string `json:"xact_continued_time"`
		Query_start            string `json:"query_start"`
		Query_continued_time   string `json:"query_continued_time"`
		Wait_event_type        string `json:"wait_event_type"`
		Wait_event             string `json:"wait_event"`
		State                  string `json:"state"`
		Query                  string `json:"query"`
	}

	//定义列表返回的struct
	type ListData struct {
		Total int    `json:"total"`
		Rows  []List `json:"rows"`
	}

	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "lockadmin_lock_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "管理工具－－进程管理－－获取某个数据库或所有数据库的受阻塞锁列表－－节点ID号为[" + r.FormValue("id") + "]－－数据库datname为[" + r.FormValue("datname") + "]－－"

	//判断节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = error_msg + "节点id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	noderow := <-row_chan
	if noderow.Return_code == "FAIL" {
		error_msg = error_msg + "获取节点资料失败－－详情：" + noderow.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = noderow.Host
	config.User = noderow.Pg_user
	config.Password = noderow.Pg_password
	config.Database = noderow.Pg_database
	config.Port = noderow.Pg_port
	conn, err = pgx.Connect(config)
	if err != nil {
		error_msg = error_msg + "连接数据库失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql := ""
	var rows *pgx.Rows

	where := " WHERE pg_locks.granted=false AND pg_locks.pid!=pg_backend_pid() "
	if r.FormValue("datname") != "" {
		where = where + " AND pg_stat_activity.datname='" + sql_data_encode(r.FormValue("datname")) + "' "
	}

	sql = `
	SELECT
	    pg_locks.locktype, 
	    pg_locks.pid,
	    pg_locks.mode,
		case pg_locks.mode    
		   when 'INVALID' then 0   
		   when 'AccessShareLock' then 1   
		   when 'RowShareLock' then 2   
		   when 'RowExclusiveLock' then 3   
		   when 'ShareUpdateExclusiveLock' then 4   
		   when 'ShareLock' then 5   
		   when 'ShareRowExclusiveLock' then 6   
		   when 'ExclusiveLock' then 7   
		   when 'AccessExclusiveLock' then 8   
		   else 0   
		end::integer AS mode_level,
	    pg_locks.granted::text,
	    COALESCE(pg_stat_activity.datname,'') AS datname,
	    COALESCE(pg_namespace.nspname,'') AS nspname,
	    COALESCE(pg_class.relname,'') AS relname, 	    
	    COALESCE(pg_class.relkind::text,'') AS relkind,   
	    COALESCE(pg_locks.page::TEXT,'') AS page,
	    COALESCE(pg_locks.tuple::TEXT,'') AS tuple,
	    COALESCE(pg_locks.transactionid::TEXT,'') AS transactionid,
	    pg_stat_activity.client_addr::text,
	    pg_stat_activity.usename,
	    pg_stat_activity.application_name,
	    pg_stat_activity.backend_start::timestamp(0)::text,
	    (now()::timestamp(0)-pg_stat_activity.backend_start::timestamp(0))::text AS backend_continued_time,
	    COALESCE(pg_stat_activity.xact_start::timestamp(0)::text,'') AS xact_start,
	    COALESCE((now()::timestamp(0)-pg_stat_activity.xact_start::timestamp(0))::text,'') AS xact_continued_time,
	    COALESCE(pg_stat_activity.query_start::timestamp(0)::text,'') AS query_start,
	    COALESCE((now()::timestamp(0)-pg_stat_activity.query_start::timestamp(0))::text,'') AS query_continued_time,
		COALESCE(pg_stat_activity.wait_event_type,'') AS wait_event_type ,
		COALESCE(pg_stat_activity.wait_event,'') AS wait_event,
	    pg_stat_activity.state,
	    pg_stat_activity.query
	FROM 
	    pg_catalog.pg_locks AS pg_locks 
	    LEFT OUTER JOIN pg_catalog.pg_class AS pg_class ON pg_class.oid=pg_locks.relation
	    LEFT OUTER JOIN pg_catalog.pg_namespace AS pg_namespace ON pg_namespace.oid=pg_class.relnamespace
	    LEFT OUTER JOIN pg_catalog.pg_stat_activity AS pg_stat_activity ON pg_stat_activity.pid=pg_locks.pid	
	` + where + sql_sort(r)

	rows, err = conn.Query(sql)
	defer rows.Close()

	if err != nil {
		error_msg = error_msg + "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	var data ListData = ListData{}
	data.Rows = make([]List, 0)
	data.Total = 0

	for rows.Next() {
		var row List
		err = rows.Scan(
			&row.Locktype,
			&row.Pid,
			&row.Mode,
			&row.Mode_level,
			&row.Granted,
			&row.Datname,
			&row.Nspname,
			&row.Relname,
			&row.Relkind,
			&row.Page,
			&row.Tuple,
			&row.Transactionid,
			&row.Client_addr,
			&row.Usename,
			&row.Application_name,
			&row.Backend_start,
			&row.Backend_continued_time,
			&row.Xact_start,
			&row.Xact_continued_time,
			&row.Query_start,
			&row.Query_continued_time,
			&row.Wait_event_type,
			&row.Wait_event,
			&row.State,
			&row.Query)
		if err != nil {
			error_msg = error_msg + "执行查询失败，详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		data.Rows = append(data.Rows, row)
	}
	data.Total = len(data.Rows)
	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：管理工具－－进程管理－－获取阻塞某个进程的锁列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func lockadmin_cloglock_listHandler(w http.ResponseWriter, r *http.Request) {
	//节点行信息json结构
	type List struct {
		Locktype               string `json:"locktype"`
		Pid                    int64  `json:"pid"`
		Mode                   string `json:"mode"`
		Mode_level             int32  `json:"mode_level"`
		Granted                string `json:"granted"`
		Datname                string `json:"datname"`
		Nspname                string `json:"nspname"`
		Relname                string `json:"relname"`
		Relkind                string `json:"relkind"`
		Page                   string `json:"page"`
		Tuple                  string `json:"tuple"`
		Transactionid          string `json:"transactionid"`
		Client_addr            string `json:"client_addr"`
		Usename                string `json:"usename"`
		Application_name       string `json:"application_name"`
		Backend_start          string `json:"backend_start"`
		Backend_continued_time string `json:"backend_continued_time"`
		Xact_start             string `json:"xact_start"`
		Xact_continued_time    string `json:"xact_continued_time"`
		Query_start            string `json:"query_start"`
		Query_continued_time   string `json:"query_continued_time"`
		Wait_event_type        string `json:"wait_event_type"`
		Wait_event             string `json:"wait_event"`
		State                  string `json:"state"`
		Query                  string `json:"query"`
	}

	//定义列表返回的struct
	type ListData struct {
		Total int    `json:"total"`
		Rows  []List `json:"rows"`
	}

	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "lockadmin_cloglock_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "管理工具－－进程管理－－获取某个数据库或所有数据库的受阻塞锁列表－－节点ID号为[" + r.FormValue("id") + "]－－进程号pid值为[" + r.FormValue("pid") + "]－－"

	//判断pid合法性
	_, err := strconv.Atoi(r.FormValue("pid"))
	if err != nil {
		error_msg = error_msg + "进程号pid不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//判断节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = error_msg + "节点id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	noderow := <-row_chan
	if noderow.Return_code == "FAIL" {
		error_msg = error_msg + "获取节点资料失败－－详情：" + noderow.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = noderow.Host
	config.User = noderow.Pg_user
	config.Password = noderow.Pg_password
	config.Database = noderow.Pg_database
	config.Port = noderow.Pg_port
	conn, err = pgx.Connect(config)
	if err != nil {
		error_msg = error_msg + "连接数据库失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql := ""
	var rows *pgx.Rows

	sql = `
	SELECT 
	   pg_proc.proname 
	FROM
	   pg_catalog.pg_proc as pg_proc 
	   INNER JOIN pg_catalog.pg_namespace AS pg_namespace ON pg_namespace.oid=pg_proc.pronamespace 
	WHERE 
	   pg_proc.proname='pg_blocking_pids' 
	   AND pg_namespace.nspname='pg_catalog';
	`
	rows, err = conn.Query(sql)
	if err != nil {
		error_msg = error_msg + "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	where := ""
	if rows.Next() {
		where = "AND pg_locks.pid IN (SELECT pid::integer FROM (SELECT regexp_split_to_table(array_to_string(pg_blocking_pids(" + sql_data_encode(r.FormValue("pid")) + "),','),',') AS pid) AS pg_blocking_pids)"
	}
	rows.Close()

	sql = `
	SELECT
	    pg_locks.locktype, 
	    pg_locks.pid,
	    pg_locks.mode,
		case pg_locks.mode    
		   when 'INVALID' then 0   
		   when 'AccessShareLock' then 1   
		   when 'RowShareLock' then 2   
		   when 'RowExclusiveLock' then 3   
		   when 'ShareUpdateExclusiveLock' then 4   
		   when 'ShareLock' then 5   
		   when 'ShareRowExclusiveLock' then 6   
		   when 'ExclusiveLock' then 7   
		   when 'AccessExclusiveLock' then 8   
		   else 0   
		end::integer AS mode_level,
	    pg_locks.granted::text,
	    COALESCE(pg_stat_activity.datname,'') AS datname,
	    COALESCE(pg_namespace.nspname,'') AS nspname,
	    COALESCE(pg_class.relname,'') AS relname, 	    
	    COALESCE(pg_class.relkind::text,'') AS relkind,   
	    COALESCE(pg_locks.page::TEXT,'') AS page,
	    COALESCE(pg_locks.tuple::TEXT,'') AS tuple,
	    COALESCE(pg_locks.transactionid::TEXT,'') AS transactionid,
	    pg_stat_activity.client_addr::text,
	    pg_stat_activity.usename,
	    pg_stat_activity.application_name,
	    pg_stat_activity.backend_start::timestamp(0)::text,
	    (now()::timestamp(0)-pg_stat_activity.backend_start::timestamp(0))::text AS backend_continued_time,
	    COALESCE(pg_stat_activity.xact_start::timestamp(0)::text,'') AS xact_start,
	    COALESCE((now()::timestamp(0)-pg_stat_activity.xact_start::timestamp(0))::text,'') AS xact_continued_time,
	    COALESCE(pg_stat_activity.query_start::timestamp(0)::text,'') AS query_start,
	    COALESCE((now()::timestamp(0)-pg_stat_activity.query_start::timestamp(0))::text,'') AS query_continued_time,
		COALESCE(pg_stat_activity.wait_event_type,'') AS wait_event_type ,
		COALESCE(pg_stat_activity.wait_event,'') AS wait_event,
	    pg_stat_activity.state,
	    pg_stat_activity.query
	FROM 
	    pg_catalog.pg_locks AS pg_locks 
	    LEFT OUTER JOIN pg_catalog.pg_class AS pg_class ON pg_class.oid=pg_locks.relation
	    LEFT OUTER JOIN pg_catalog.pg_namespace AS pg_namespace ON pg_namespace.oid=pg_class.relnamespace
	    INNER JOIN pg_catalog.pg_stat_activity AS pg_stat_activity ON pg_stat_activity.pid=pg_locks.pid
		INNER JOIN pg_catalog.pg_locks AS clog ON (
			pg_locks.locktype is not distinct from clog.locktype   
		    AND pg_locks.database is not distinct from clog.database   
		    AND pg_locks.relation is not distinct from clog.relation   
		    AND pg_locks.page is not distinct from clog.page   
		    AND pg_locks.tuple is not distinct from clog.tuple   
		    AND pg_locks.virtualxid is not distinct from clog.virtualxid   
		    AND pg_locks.transactionid is not distinct from clog.transactionid   
		    AND pg_locks.classid is not distinct from clog.classid   
		    AND pg_locks.objid is not distinct from clog.objid   
		    AND pg_locks.objsubid is not distinct from clog.objsubid 
			AND clog.pid=` + sql_data_encode(r.FormValue("pid")) + ` 
			AND pg_locks.pid!=` + sql_data_encode(r.FormValue("pid")) + ` 
			AND clog.granted=false 	
			` + where + `		
		)	
	` + sql_sort(r)

	rows, err = conn.Query(sql)
	defer rows.Close()

	if err != nil {
		error_msg = error_msg + "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	var data ListData = ListData{}
	data.Rows = make([]List, 0)
	data.Total = 0

	for rows.Next() {
		var row List
		err = rows.Scan(
			&row.Locktype,
			&row.Pid,
			&row.Mode,
			&row.Mode_level,
			&row.Granted,
			&row.Datname,
			&row.Nspname,
			&row.Relname,
			&row.Relkind,
			&row.Page,
			&row.Tuple,
			&row.Transactionid,
			&row.Client_addr,
			&row.Usename,
			&row.Application_name,
			&row.Backend_start,
			&row.Backend_continued_time,
			&row.Xact_start,
			&row.Xact_continued_time,
			&row.Query_start,
			&row.Query_continued_time,
			&row.Wait_event_type,
			&row.Wait_event,
			&row.State,
			&row.Query)
		if err != nil {
			error_msg = error_msg + "执行查询失败，详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		data.Rows = append(data.Rows, row)
	}
	data.Total = len(data.Rows)
	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：管理工具－－表锁管理－－取消查询

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func lockadmin_cancelqueryHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "lockadmin_cancelqueryHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "管理工具－－表锁管理－－取消查询－－节点ID号为[" + r.FormValue("id") + "]－－要取消查询的pid为[" + r.FormValue("pid") + "]－－"

	ret_code, ret_result := precess_cancelquery(r.FormValue("id"), r.FormValue("pid"))
	if ret_code == "FAIL" {
		error_msg = error_msg + ret_result
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	} else {
		logcontent := error_msg + ret_result
		OutputJson(w, "SUCCESS", "执行成功！", 0)
		go write_log(remote_ip, modlename, username, "Log", logcontent)
		return
	}
}

/*
功能描述：管理工具－－表锁管理－－杀死进程

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func lockadmin_killprocessHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "lockadmin_killprocessHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "管理工具－－表锁管理－－杀死进程－－节点ID号为[" + r.FormValue("id") + "]－－要杀死的pid为[" + r.FormValue("pid") + "]－－"

	ret_code, ret_result := precess_killprecess(r.FormValue("id"), r.FormValue("pid"))
	if ret_code == "FAIL" {
		error_msg = error_msg + ret_result
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	} else {
		logcontent := error_msg + ret_result
		OutputJson(w, "SUCCESS", "执行成功！", 0)
		go write_log(remote_ip, modlename, username, "Log", logcontent)
		return
	}
}

/*
功能描述：管理工具－－查询统计－－检查要查询的节点是否加载了pg_stat_statments

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func querycount_pg_stat_statments_load_checkHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "querycount_pg_stat_statments_load_checkHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "管理工具－－查询统计－－获取某个数据库的查询统计时检查是否加载了pg_stat_statments－－节点ID号为[" + r.FormValue("id") + "]－－"
	//判断节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = error_msg + "节点id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	noderow := <-row_chan
	if noderow.Return_code == "FAIL" {
		error_msg = error_msg + "获取节点资料失败－－详情：" + noderow.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = noderow.Host
	config.User = noderow.Pg_user
	config.Password = noderow.Pg_password
	config.Database = noderow.Pg_database
	config.Port = noderow.Pg_port
	conn, err = pgx.Connect(config)
	if err != nil {
		error_msg = error_msg + "连接数据库失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()
	sql := "SELECT current_setting( 'shared_preload_libraries' ) AS shared_preload_libraries,COALESCE((SELECT extname FROM pg_catalog.pg_extension WHERE extname='pg_stat_statements' limit 1),'') AS extname"
	rows, err := conn.Query(sql)
	defer rows.Close()

	if err != nil {
		error_msg = error_msg + "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	if rows.Next() {
		var shared_preload_libraries string
		var extname string
		err = rows.Scan(&shared_preload_libraries, &extname)
		if err != nil {
			error_msg = error_msg + "执行查询失败，详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		if !strings.Contains(shared_preload_libraries, "pg_stat_statements") {
			ret := "该节点还没有配置pg_stat_statements模块，无法对查询进行统计。"
			OutputJson(w, "FAIL", ret, 0)
			go write_log(remote_ip, modlename, username, "Log", error_msg+ret)
			return
			return
		}
		if extname != "pg_stat_statements" {
			ret := "数据库[" + noderow.Pg_database + "]还没加载pg_stat_statments，请给连接的数据库加载pg_stat_statments模块"
			OutputJson(w, "FAIL", ret, 0)
			go write_log(remote_ip, modlename, username, "Log", error_msg+ret)
			return
			return
		}
		ret := "数据库[" + noderow.Pg_database + "]已经加载pg_stat_statments"
		OutputJson(w, "SUCCESS", ret, 0)
		go write_log(remote_ip, modlename, username, "Log", error_msg+ret)
		return
	} else {
		error_msg = error_msg + "提取数据失败"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
}

/*
功能描述：管理工具－－查询统计－－重新统计

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func querycount_dialog_countresetHandler(w http.ResponseWriter, r *http.Request) {
	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "querycount_dialog_countresetHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "管理工具－－查询统计－－重新统计重置节点ID号为[" + r.FormValue("id") + "]－－"
	//判断节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = error_msg + "节点id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	noderow := <-row_chan
	if noderow.Return_code == "FAIL" {
		error_msg = error_msg + "获取节点资料失败－－详情：" + noderow.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = noderow.Host
	config.User = noderow.Pg_user
	config.Password = noderow.Pg_password
	config.Database = noderow.Pg_database
	config.Port = noderow.Pg_port
	conn, err = pgx.Connect(config)
	if err != nil {
		error_msg = error_msg + "连接数据库失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()
	sql := "SELECT pg_stat_statements_reset()"
	rows, err := conn.Query(sql)
	defer rows.Close()

	if err != nil {
		error_msg = error_msg + "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	ret := "重新统计执行成功"
	OutputJson(w, "SUCCESS", ret, 0)
	go write_log(remote_ip, modlename, username, "Log", error_msg+ret)
	return
}

/*
功能描述：管理工具－－查询统计－－获取某个数据库或所有数据库的查询统计列表

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func querycount_record_listHandler(w http.ResponseWriter, r *http.Request) {
	//节点行信息json结构
	type List struct {
		Rolname           string `json:"rolname"`
		Datname           string `json:"datname"`
		Queryid           int64  `json:"queryid"`
		Query             string `json:"query"`
		Calls             int64  `json:"calls"`
		Total_time        string `json:"total_time"`
		Min_time          string `json:"min_time"`
		Max_time          string `json:"max_time"`
		Mean_time         string `json:"mean_time"`
		Stddev_time       string `json:"stddev_time"`
		Rows              int64  `json:"rows"`
		Mean_rows         int64  `json:"mean_rows"`
		Shared_blks_hit   int64  `json:"shared_blks_hit"`
		Shared_blks_read  int64  `json:"shared_blks_read"`
		Total_shared_blks int64  `json:"total_shared_blks"`
		Mean_shared_blks  int64  `json:"mean_shared_blks"`
	}

	//定义列表返回的struct
	type ListData struct {
		Total int    `json:"total"`
		Rows  []List `json:"rows"`
	}

	var error_msg string
	remote_ip := get_remote_ip(r)
	modlename := "lockadmin_lock_listHandler"
	username := http_init(w, r)
	if username == "" {
		OutputJson(w, "FAIL", "系统无法识别你的身份", 1)
		return
	}
	error_msg = "管理工具－－查询统计－－获取某个数据库的查询统计－－节点ID号为[" + r.FormValue("id") + "]－－数据库datname为[" + r.FormValue("datname") + "]－－"

	//判断节点id合法性
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		error_msg = error_msg + "节点id号不是合法的int类型"
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	noderow := <-row_chan
	if noderow.Return_code == "FAIL" {
		error_msg = error_msg + "获取节点资料失败－－详情：" + noderow.Return_msg
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	//连接数据库
	var conn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = noderow.Host
	config.User = noderow.Pg_user
	config.Password = noderow.Pg_password
	config.Database = noderow.Pg_database
	config.Port = noderow.Pg_port
	conn, err = pgx.Connect(config)
	if err != nil {
		error_msg = error_msg + "连接数据库失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}
	defer conn.Close()

	sql := ""
	var rows *pgx.Rows

	where := ""
	if r.FormValue("datname") != "" {
		where = where + " WHERE pg_database.datname='" + sql_data_encode(r.FormValue("datname")) + "' "
	}

	//异步获取总记录数
	sql = "SELECT COUNT(1) AS num FROM pg_stat_statements INNER JOIN pg_catalog.pg_database AS pg_database on pg_database.oid= pg_stat_statements.dbid " + where
	total_chan := make(chan Totalnum)
	go getnode_totalnum(noderow.Id, sql, total_chan)

	sql = `
	SELECT 
	    pg_authid.rolname as rolname,
	    pg_database.datname as datname,
		pg_stat_statements.queryid,
	    pg_stat_statements.query,
	    pg_stat_statements.calls,
	    round(pg_stat_statements.total_time::numeric,3)::text AS total_time,
	    round(pg_stat_statements.min_time::numeric,3)::text AS min_time,   
	    round(pg_stat_statements.max_time::numeric,3)::text AS max_time,   
	    round(pg_stat_statements.mean_time::numeric,3)::text AS mean_time,    
	    round(pg_stat_statements.stddev_time::numeric,3)::text AS stddev_time,   
	    pg_stat_statements.rows, 
	    (pg_stat_statements.rows/pg_stat_statements.calls)::bigint AS mean_rows, 
	    pg_stat_statements.shared_blks_hit,
	    pg_stat_statements.shared_blks_read,
	    (pg_stat_statements.shared_blks_hit+pg_stat_statements.shared_blks_read) as total_shared_blks,
		((pg_stat_statements.shared_blks_hit+pg_stat_statements.shared_blks_read)/pg_stat_statements.calls)::bigint AS mean_shared_blks
	FROM 
	    pg_stat_statements
	    INNER JOIN pg_catalog.pg_authid AS pg_authid on pg_authid.oid=pg_stat_statements.userid 
	    INNER JOIN pg_catalog.pg_database AS pg_database on pg_database.oid= pg_stat_statements.dbid		
	` + where + sql_sort_limit(r)
	rows, err = conn.Query(sql)
	defer rows.Close()

	if err != nil {
		error_msg = error_msg + "执行查询失败，详情：" + err.Error()
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	var data ListData = ListData{}
	data.Rows = make([]List, 0)
	data.Total = 0

	for rows.Next() {
		var row List
		err = rows.Scan(
			&row.Rolname,
			&row.Datname,
			&row.Queryid,
			&row.Query,
			&row.Calls,
			&row.Total_time,
			&row.Min_time,
			&row.Max_time,
			&row.Mean_time,
			&row.Stddev_time,
			&row.Rows,
			&row.Mean_rows,
			&row.Shared_blks_hit,
			&row.Shared_blks_read,
			&row.Total_shared_blks,
			&row.Mean_shared_blks)
		if err != nil {
			error_msg = error_msg + "执行查询失败，详情：" + err.Error()
			OutputJson(w, "FAIL", error_msg, 0)
			go write_log(remote_ip, modlename, username, "Error", error_msg)
			return
		}
		data.Rows = append(data.Rows, row)
	}

	//返回异步获取总记录数
	total := <-total_chan
	if total.Err == "" {
		data.Total = total.Total
	} else {
		error_msg = error_msg + total.Err
		OutputJson(w, "FAIL", error_msg, 0)
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return
	}

	data.Total = total.Total
	ret, _ := json.Marshal(data)
	w.Write(ret)
}

/*
功能描述：precess_cancelquery 取消指定进程的当前查询

参数说明：
nodeid   -- 字符类型，节点的id号
process_pid --字符类型，进程号拼接字符串，如998,999,1000

返回值说明：
return_code -- 返回错误代号，值为FAIL或者SUCCESS
return_msg  -- 返回错误或成功的详细信息
*/

func precess_cancelquery(nodeid string, process_pid string) (return_code string, return_msg string) {
	//判断节点id合法性
	id, err := strconv.Atoi(nodeid)
	if err != nil {
		return_code = "FAIL"
		return_msg = "节点id号不是合法的int类型"
		return
	}

	//判断pid是否合法
	if process_pid == "" {
		return_code = "FAIL"
		return_msg = "要取消查询的pid值为空"
		return
	}

	//获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	noderow := <-row_chan
	if noderow.Return_code == "FAIL" {
		return_code = "FAIL"
		return_msg = "获取节点资料失败－－详情：" + noderow.Return_msg
		return
	}

	//连接数据库
	var conn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = noderow.Host
	config.User = noderow.Pg_user
	config.Password = noderow.Pg_password
	config.Database = noderow.Pg_database
	config.Port = noderow.Pg_port
	conn, err = pgx.Connect(config)
	if err != nil {
		return_code = "FAIL"
		return_msg = "连接数据库失败，详情：" + err.Error()
		return
	}
	defer conn.Close()

	sql := ""
	var rows *pgx.Rows

	sql = `
	SELECT array_to_json(array
	(
		SELECT
			row_to_json(t.*)
		FROM
			(
				SELECT
					pg_cancel_backend(pid) as pg_cancel_backend,*
				FROM
					pg_catalog.pg_stat_activity AS pg_stat_activity
				WHERE
					pg_stat_activity.pid IN (` + sql_data_encode(process_pid) + `)
					AND pg_stat_activity.pid!=pg_catalog.pg_backend_pid()
			) AS t
	))::text AS result
	`
	rows, err = conn.Query(sql)
	defer rows.Close()

	if err != nil {
		return_code = "FAIL"
		return_msg = "执行查询失败，详情：" + err.Error()
		return
	}

	result := ""
	for rows.Next() {
		err = rows.Scan(&result)
		if err != nil {
			return_code = "FAIL"
			return_msg = "执行查询失败，详情：" + err.Error()
			return
		}
	}
	return_code = "SUCCESS"
	return_msg = result
	return

}

/*
功能描述：管理工具－－表锁管理－－杀死进程

参数说明：
w   -- http.ResponseWriter
r   -- http.Request指针

返回值说明：无
*/

func precess_killprecess(nodeid string, process_pid string) (return_code string, return_msg string) {
	//判断节点id合法性
	id, err := strconv.Atoi(nodeid)
	if err != nil {
		return_code = "FAIL"
		return_msg = "节点id号不是合法的int类型"
		return
	}

	//判断pid是否合法
	if process_pid == "" {
		return_code = "FAIL"
		return_msg = "要杀死的进程pid值为空"
		return
	}

	//获取节点资料
	row_chan := make(chan Row)
	go get_node_row(id, row_chan)
	noderow := <-row_chan
	if noderow.Return_code == "FAIL" {
		return_code = "FAIL"
		return_msg = "获取节点资料失败－－详情：" + noderow.Return_msg
		return
	}

	//连接数据库
	var conn *pgx.Conn
	var config pgx.ConnConfig
	config.Host = noderow.Host
	config.User = noderow.Pg_user
	config.Password = noderow.Pg_password
	config.Database = noderow.Pg_database
	config.Port = noderow.Pg_port
	conn, err = pgx.Connect(config)
	if err != nil {
		return_code = "FAIL"
		return_msg = "连接数据库失败，详情：" + err.Error()
		return
	}
	defer conn.Close()

	sql := ""
	var rows *pgx.Rows

	sql = `
	SELECT array_to_json(array		
	(
		SELECT
			row_to_json(t.*)
		FROM 
			(
				SELECT 
					pg_terminate_backend(pid) as pg_terminate_backend,*
				FROM 
					pg_catalog.pg_stat_activity AS pg_stat_activity 
				WHERE 
					pg_stat_activity.pid IN (` + sql_data_encode(process_pid) + `)
					AND pg_stat_activity.pid!=pg_catalog.pg_backend_pid()
			) AS t
	))::text AS result
	`
	rows, err = conn.Query(sql)
	defer rows.Close()

	if err != nil {
		return_code = "FAIL"
		return_msg = "执行查询失败，详情：" + err.Error()
		return
	}

	result := ""
	for rows.Next() {
		err = rows.Scan(&result)
		if err != nil {
			return_code = "FAIL"
			return_msg = "执行查询失败，详情：" + err.Error()
			return
		}
	}

	return_code = "SUCCESS"
	return_msg = result
	return
}

/*
功能描述：vacuumdb一个节点

参数说明：
nodeid   -- 节点的id号

返回值说明：
errmsg -- 返回错误信息
*/

func vacuumdb(nodeid int, remote_ip string, username string) (errmsg string) {
	var error_msg string
	modlename := "vacuumdb"
	//异步获取节点资料
	row_chan := make(chan Row)
	go get_node_row(nodeid, row_chan)
	row := <-row_chan
	if row.Return_code == "FAIL" {
		error_msg = "获取节点[ " + fmt.Sprintf("%d", nodeid) + " ]资料失败,详情：" + row.Return_msg
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return error_msg
	}
	//执行全库vacuum
	cmd := "export PGPASSWORD=" + row.Pg_password
	cmd = cmd + ";" + row.Pg_bin + "vacuumdb -a -z -w -h " + row.Host + " -p " + fmt.Sprintf("%d", row.Pg_port) + " -U " + row.Pg_user
	_, stderr := ssh_run(row.Ssh_authmethod, "postgres", row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
	if stderr != "" {
		error_msg = "执行vacuumdb出错[ " + fmt.Sprintf("%d", nodeid) + " ]详情：" + stderr
		go write_log(remote_ip, modlename, username, "Error", error_msg)
		return error_msg
	}
	error_msg = "执行vacuumdb成功[ " + fmt.Sprintf("%d", nodeid) + " ]"
	go write_log(remote_ip, modlename, username, "Log", error_msg)
	return ""
}

/*
功能描述：拼接查询列表之排序字符串

参数说明：
r -- http.Request指针

返回值说明：
返回拼接好的查询字符串
*/

func sql_sort(r *http.Request) string {
	var order_fields string
	var order_type string

	order_fields = r.FormValue("sort")
	order_type = r.FormValue("order")

	if order_fields == "" {
		order_fields = "1"
	}
	if (order_type != "" && order_type != "asc" && order_type != "desc") || order_type == "" {
		order_type = "asc"
	}
	return " ORDER BY " + sql_data_encode(order_fields) + " " + sql_data_encode(order_type)
}

/*
功能描述：拼接查询列表之排序，分页查询字符串

参数说明：
r -- http.Request指针

返回值说明：
返回拼接好的查询字符串
*/

func sql_sort_limit(r *http.Request) string {
	var order_fields string
	var order_type string

	order_fields = r.FormValue("sort")
	order_type = r.FormValue("order")

	if order_fields == "" {
		order_fields = "1"
	}
	if (order_type != "" && order_type != "asc" && order_type != "desc") || order_type == "" {
		order_type = "asc"
	}

	//判断每页记录数参数的合法性
	limit, err := strconv.Atoi(r.FormValue("rows"))
	if err != nil || limit < 1 {
		limit = 100
	}

	//判断page合法性
	offset, err := strconv.Atoi(r.FormValue("page"))
	if err != nil || offset < 1 {
		offset = 0
	} else {
		offset = (offset - 1) * limit
	}

	return " ORDER BY " + sql_data_encode(order_fields) + " " + sql_data_encode(order_type) + " OFFSET " + fmt.Sprintf("%d", offset) + " LIMIT " + fmt.Sprintf("%d", limit)

}

/*
功能描述：sql查询拼接字符串编码

参数说明：
str -- 要编码的字符串

返回值说明：
返回编码过的字符串

*/

func sql_data_encode(str string) string {
	return strings.Replace(str, "'", "''", -1)
}

/*
功能描述：生成返回json数据

参数说明：
w   -- http.ResponseWriter
return_code  --返回code代码,分别是FAIL,SUCCESS
return_msg   --返回提示详情
login_dialog --是否显示登录对话框

返回值说明：无
*/

func OutputJson(w http.ResponseWriter, return_code string, return_msg string, login_dialog int) {
	out := &Result{return_code, return_msg, login_dialog}
	b, _ := json.Marshal(out)
	w.Write(b)
}

/*
功能描述：生成返回json数据

参数说明：
authmethod --ssh认证方法，key（私钥登陆）或者password（密码登录）
user      --ssh登录用户名
password  --ssh登录用户密码
host      --ssh访问主机ip或host
port      --ssh服务的port

返回值说明：
session   --ssh.Session连接指针
error     --error对象
*/

func ssh_connect(authmethod string, user string, password string, host string, port int) (*ssh.Client, *ssh.Session, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		session      *ssh.Session
		err          error
	)

	auth = make([]ssh.AuthMethod, 0)
	if authmethod == "password" {
		auth = append(auth, ssh.Password(password))
	} else {
		pemBytes := []byte(password)
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return nil, nil, err
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	clientConfig = &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: 30 * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	addr = fmt.Sprintf("%s:%d", host, port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, nil, err
	}

	if session, err = client.NewSession(); err != nil {
		client.Close()
		return nil, nil, err
	}

	return client, session, nil
}

/*
功能描述：ssh上主机并执行命令，返回执行的结果及错误

参数说明：
authmethod --ssh认证方法，key（私钥登陆）或者password（密码登录）
user_level --用户级别，分别postgres和root
user      --ssh登录用户名
password  --ssh登录用户密码
host      --ssh访问主机ip或host
port      --ssh服务的port
cmd       --要执行的脚本

返回值说明：
return_stdout  --返回执行返回的输出信息
return_stderr  --返回执行返回的出错信息
*/

func ssh_run(authmethod string, user_level string, user string, password string, host string, port int, cmd string) (return_stdout string, return_stderr string) {
	//ssh连接
	if authmethod != "key" && authmethod != "password" {
		return "", "authmethod值[" + authmethod + "]不合法"
	}
	if user_level != "postgres" && user_level != "root" {
		return "", "user_level值[" + user_level + "]不合法"
	}
	if authmethod == "key" {
		if user_level == "postgres" {
			password = get_postgres_private_key()
		} else {
			password = get_root_private_key()
		}
	}
	client, session, err := ssh_connect(authmethod, user, password, host, port)
	if err != nil {
		return "", err.Error()
	}

	defer session.Close()
	defer client.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	session.Run(cmd)
	return stdout.String(), stderr.String()
}

/*
功能描述：异步--ssh上主机并执行命令，返回执行的结果及错误

参数说明：
authmethod --ssh认证方法，key（私钥登陆）或者password（密码登录）
user_level --用户级别，分别postgres和root
user      --ssh登录用户名
password  --ssh登录用户密码
host      --ssh访问主机ip或host
port      --ssh服务的port
cmd       --要执行的脚本

返回值说明：
s -- 结构体Stdout_and_stderr变量
*/

func ssh_run_chan(authmethod string, user_level string, user string, password string, host string, port int, cmd string, s chan Stdout_and_stderr) {
	//定义返回的struct
	var out Stdout_and_stderr
	if authmethod != "key" && authmethod != "password" {
		out.Stdout = ""
		out.Stderr = "authmethod值[" + authmethod + "]不合法"
		s <- out
		return
	}
	if user_level != "postgres" && user_level != "root" {
		out.Stdout = ""
		out.Stderr = "user_level值[" + user_level + "]不合法"
		s <- out
		return
	}
	if authmethod == "key" {
		if user_level == "postgres" {
			password = get_postgres_private_key()
		} else {
			password = get_root_private_key()
		}
	}
	//ssh连接

	client, session, err := ssh_connect(authmethod, user, password, host, port)
	if err != nil {
		out.Stdout = ""
		out.Stderr = err.Error()
		s <- out
		return
	}

	defer session.Close()
	defer client.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	session.Run(cmd)

	out.Stdout = stdout.String()
	out.Stderr = stderr.String()
	s <- out
	return
}

/*
功能描述：写入日志处理

参数说明：
remote_ip -- 访问客户端地址
modlename -- 访问模块
username  -- 操作员账号
log_level -- 日志级别，只能是是Error或Log
error_msg -- 日志内容

返回值说明：无
*/

func write_log(remote_ip string, modlename string, username string, log_level string, error_msg string) {
	//打印错误信息
	fmt.Println("访问时间：", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("访问ip：", remote_ip)
	fmt.Println("模块名称：", modlename)
	fmt.Println("操作用户：", username)
	fmt.Println("日志级别：", log_level)
	fmt.Println("详细信息：", error_msg)
	//连接数据库，保存日志
	var conn *pgx.Conn
	conn, err := pgx.Connect(extractConfig())
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	_, err = conn.Exec("insert into log(remote_ip,modlename,username,log_level,remark) values($1,$2,$3,$4,$5)", remote_ip, modlename, username, log_level, error_msg)
	if err != nil {
		fmt.Println(err)
		return
	}
}

/*
功能描述：获取访问端的ip地址

参数说明：
r -- http.Request指针

返回值说明：
remote_ip -- 访问的客户端ip地址
*/

func get_remote_ip(r *http.Request) (remote_ip string) {
	ips := strings.Split(r.RemoteAddr, ":")
	return ips[0]
}

/*
功能描述：获取访问端的ip地址

参数说明：
w -- http.ResponseWriter
r -- http.Request指针

返回值说明：
username -- 操作号账号
*/

func http_init(w http.ResponseWriter, r *http.Request) (username string) {
	w.Header().Set("content-type", "application/json")
	sess := globalSessions.SessionStart(w, r)
	session_username := sess.Get("username")
	if session_username == nil {
		return ""
	} else {
		return fmt.Sprintf("%v", session_username)
	}
}

/*
功能描述：判断字符串是否为整数

参数说明：
val -- 要判断的字符串

返回值说明：
ret_val -- true 或 false
*/

func str_is_int(val string) (ret_val bool) {
	_, err := strconv.Atoi(val)
	if err == nil {
		return true
	} else {
		return false
	}
}

/*
功能描述：判断字符串是否全法ip地址

参数说明：
val -- 要判断的字符串

返回值说明：
ret_val -- true 或 false
*/

func str_is_ip(val string) (ret_val bool) {
	bits := strings.Split(val, ".")
	len := len(bits)
	if len != 4 {
		return false
	}
	for i := 0; i < len; i++ {
		v, err := strconv.Atoi(bits[i])
		if err != nil {
			return false
		}
		if v < 0 || v > 255 {
			return false
		}
	}
	return true
}

/*
功能描述：配置postgresql连接参数

参数说明：无

返回值说明：
pgx.ConnConfig -- pg连接参数结构体
*/

func extractConfig() pgx.ConnConfig {

	var config pgx.ConnConfig

	config.Host = "127.0.0.1"     //数据库主机host或ip
	config.User = "postgres"      //连接用户
	config.Password = "pgsql"     //用户密码
	config.Database = "pgcluster" //连接数据库名
	config.Port = 5432            //端口号

	return config
}

/*
功能描述：返回postgres用户的私钥证书

参数说明：无

返回值说明：
key -- postgres用户的私钥证书,证书类型可以是“DSA”或“RSA”
*/

func get_postgres_private_key() (key string) {
	postgres_private_key := `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxPeKBh8JRa7uz7Sf5qyOCxlUN5+QAKszbbJZMTKqVM3UMqrR
lMyKEwrzEaK4WP6wkLiiiYAsOtkeemaOTNFwwSJ1uztIh2HaU1W+SSxxBTP+D6wl
UAGnjrTXU321gMAA2FV90Xllb/RZL66YKbOEhAXj1OWnBwrcfU7zK3A3VdS/qsNe
nH65UbeFaBYi1xfQwKmvRvMgIN3ABRMSaabNsRWOU2Udp54NEEtMXYszDVGB4Bg3
G4DQLborUDmYJvQ1lb4Kzdx5QIOVD+vypMzh6CL1JreGvCxj9XCuUIFD+oUjGrTZ
X2xq2e1W+YfZzGLbDCguX8Ip7+hZw9zMdLtHeQIBIwKCAQBlTBsZF0aY3Z9jgXbO
Z17+ZMw53Qg627QMh5uVpQckTJkEHVXXfyJwMYRSNm1vmO0XOmI4FggeQ8aIF3xi
BU/uTDyMLR38e3eYkn8eUV6yN/8Avu6eLLySiOPEicsPA6ipxZEp5qkyQyaNjP3M
TbHdf186SjikiT4x0NTUgtqhKq6VgRCr6E+tLJH0k+KYqGNHqkUIluzjHtJKIAen
JH+//8m4ZNEXP5u+1RYXVxY38o2tOgyGYsGvOW0K0tLwvx/N+EmgPFJk6gp/nVfT
VyvB4BKC2TobLJS93+d81b9BwURl++tWriSSu83khXzlonOAw8NLx8L3AJZpeg0F
f1zjAoGBAOqRngGvaHPH5uuprSDjpopNhnk0APyAo4LiG+pRg95P5VbhAR1dqiZi
2pTnzhuoK9lWaDr/Kk5U/b1yUm2IgsXItYruTcsDgeJUa2RE944ZUMJOxX3/bQoZ
6US1KEGp7WNthdGWYp4JpLiciltWoVHDvBryfpXU0zt6ySPa10srAoGBANb2cYOe
0o4q3X3xEJB1RkyEO6/Xk8jKKPmS1VIaP4Uy971vZxRj28YPtfAPd0+/eLF/+AAz
egk86TZI23QDNrH1bNREbrixrGVuB4AMASlkEEe9EsJrduNN4kPvuWPCg4HKb9qg
fkzPaap1+e8pBaixmhevPyc6zN1fieSdbFXrAoGBAN0qNeRU7XR6poZsx86Nf8Q6
d3mXbqTuUQZgKPLfJI/HrFk6jAW+tl60+focYz6l4DNReDegIJL/rWl6avmPVrp7
aVcbM2ekOKIyVqBeSH6qJ5KiCqn/dW/si3tLuD3pXCqL1fF/Kcg0+mTrXeEXKmMJ
AdBDuS4vEE4GDhp94O8ZAoGAN0aveZ3eXxJWNlPuUQg2pfYd+gQ78c2VggEviiQB
tIly55GsyrqXmVR/PbrViYkBxz4p1Cp+d2dvKzdOX6kOEIDwGVNs7aoHwk9+RX9u
A1Q+s1yBKq3rXwVmEXgoW3spIV/w4HJpnrj96gEUYhHc4jxMMfndChZvMZw5Zqwj
LAkCgYEA3/ojt688iVipMQnf4lZ2J+wYCpiFUzDj2JxJDbDRbruIT+VFO/kC4qFE
6sq9zRcKfKZz/9ZHHZ/JiTB64REA/y/fmZjRDZtHaZo/Icmg4UJsxQKz9kpx6dzY
iIwwbdcIMoPl5G+fImQub0uMvkD/QmM2iR7yLGrPPNeLFa1fMT8=
-----END RSA PRIVATE KEY-----`
	return postgres_private_key
}

/*
功能描述：返回root用户的私钥证书

参数说明：无

返回值说明：
key -- root用户的私钥证书,证书类型可以是“DSA”或“RSA”
*/

func get_root_private_key() (key string) {
	root_private_key := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAv42IZYba1epN/CFflInYpg1I1XUr7zdazwLClpJH3I1ykR6z
iMOKuBilzVxQbfnsid5VbQQfqPjkrxsHHkncEtTc0iHHWrxJhn4jU1Jj/h280Nk4
H27+hKcB6ZRVfmQ4SzPIG7TYFIBPaQP33NRCCcRCxBBL+YxyJwXiu1642Dip8BZa
HWCNuEPlkJV8P7HHLFhfKi8PGvdpBwf4IEGMqJwYusHmsm/BFa/Yq+ZXrLzxCXT5
HYkNenge7R+fEc+iWDtGqpBVGEO4n+f37FTKZV85F0c/TrZOh7beEoTvDgTlocfL
XOc96Gvw9SGAm11IR/K04xxGaYTPlWjZcI4h6wIBIwKCAQEAuhR13vgHyH010Frv
IpSJUNm0d5ZlMYY69Ptd8VrmuP5vSyUjbunXNn5X7BCIpVku7FRS/C/kPb6VAd+9
xabVySaNXmn028zZtdmeqLZvw6fb/hTXbv4b0VHHV+8uesfBqCOscq+tVb55Bu3p
d28blHWCr9VRHk3rO9nU8Ifmw2iQGpTWFB4B989Gph1FQrXxlTZjrXiicV5TFX5b
CUpQ6CdwkOw9UpyJYJ3RkCtOGoFYkxVrxMCwc/RVsJ52bA2zp7pwkkd8hLhbTu9j
yNS80INiPC1xAcqN8M2qRSNMLgScjiuH4vnT3JAWGR1yGzv0cqyIO2hPhAz0p+x7
FEC62wKBgQDmeyW+0dniQl8/PAX3maf4Li+hWlDJYIAY3JrY6tyKFkno9Jgq7lUj
wRryJGYlsrsz/qBwQYr6SwyfvyUbrLcBmlO3aCilKNJqP54c09iXrzKsFVWzpFut
geT/EcykeTmuPnlN2LYNf7MbkdpRiOHoVAW7ZRU8jFmD2JEByRKc5QKBgQDUwv0K
NtEw9suDQCYXtDBlXQdXM+IW+ngYwXob2QHrhTilTxhtlLW1jz27+p7pGvUPCgI/
kXP0IXeBUoSRBOxnzXp1uuHc7lksnhcwnJIlDLRcltHTkev/2TpkbkEhztWHK07b
C3tOyW/NstYMburVQaTHmznHEXhP4s3RbPymjwKBgQCxzLa3xnThviw4GFxf65A0
e2aSaj5SNIATLdaKFEO6+0BUn24SfVefPTILQKaSHCoDiel7Kz9TXndz6zniJibG
uOF+21KOCYxgl3n4+zIOnRh2HxY6H7Rv59yKQO5S/m5TN4ImHDSrU+Hwslf1wV3Q
e1ThBNXeQGJPxFKa+jLuDwKBgE8GmIAi/T4ShhrOrxAeWx5VwOXgEiXKvuSfomId
Zxz298hfNPWAYL/HfVRzB9LswWv8Zzwutgo4UPWFDKrkklJw5FedL1IPYvNQqYcV
lV436zhVRp8KUFe3FbBGNXL1DXtZOovfsXUI/aQse2O0K1aGGKHpMrenZzOdYmO6
xD3dAoGBAI+jBIuDdHsPNSM3aqYF2StwoPByTUrp9255Hxscr7YFn5Yr7nzbhlZh
jvCPjrhlEYC3ovYmW0trVtY80xL4KfloZLYH2byPGLEI7ZZqWTO5Ljf4NihHMDaO
qD4ogtyGSRriJUXQtuPGdNaQJOL4tFM4f9uiXxc1xe0tbshk7DXO
-----END RSA PRIVATE KEY-----`
	return root_private_key
}

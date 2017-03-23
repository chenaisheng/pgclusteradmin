package main

import (
 "bytes"
 "encoding/json"
 "fmt"
 "net/http"
 "strconv"
 "strings"
 "time"

 "github.com/astaxie/session"
 _ "github.com/astaxie/session/providers/memory"
 "github.com/jackc/pgx"
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
 //连接db
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
 //连接db
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
 //连接db
 var conn *pgx.Conn
 conn, err := pgx.Connect(extractConfig())
 if err != nil {
  error_msg = "连接db失败，详情：" + err.Error()
  OutputJson(w, "FAIL", error_msg, 0)
  go write_log(remote_ip, modlename, username, "Error", error_msg)
  return
 }
 defer conn.Close()

 var order_fields string
 var order_type string

 order_fields = r.FormValue("sort")
 order_type = r.FormValue("order")

 if order_fields == "" {
  order_fields = "id"
 }

 if order_type == "" {
  order_type = "asc"
 }

 order_fields_type := order_fields + " " + order_type

 sql := `
    SELECT 
        id,node_name,
        createtime::text,host,
        ssh_port,ssh_user,
        ssh_password,pg_bin,
        pg_data,pg_log,
  pg_port,pg_database,
  pg_user,pg_password,
        master_vip,master_vip_networkcard,
        slave_vip,slave_vip_networkcard,    
        bind_vip_user,bind_vip_password,     
        remark 
    FROM 
        nodes 
    ORDER BY $1
    `

 rows, err := conn.Query(sql, order_fields_type)
 if err != nil {
  error_msg = "执行查询失败，详情：" + err.Error()
  OutputJson(w, "FAIL", error_msg, 0)
  go write_log(remote_ip, modlename, username, "Error", error_msg)
  return
 }
 defer rows.Close()

 var data Data = Data{}
 data.Rows = make([]Row, 0)
 data.Total = 0
 end := make(chan Row)
 for rows.Next() {
  var row Row
  err = rows.Scan(
   &row.Id, &row.Node_name,
   &row.Createtime, &row.Host,
   &row.Ssh_port, &row.Ssh_user,
   &row.Ssh_password, &row.Pg_bin,
   &row.Pg_data, &row.Pg_log,
   &row.Pg_port, &row.Pg_database,
   &row.Pg_user, &row.Pg_password,
   &row.Master_vip, &row.Master_vip_networkcard,
   &row.Slave_vip, &row.Slave_vip_networkcard,
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
 for i := 0; i < data.Total; i++ {
  t := <-end
  data.Rows[t.Json_id].Service_type = t.Service_type
  data.Rows[t.Json_id].Service_status = t.Service_status
  data.Rows[t.Json_id].Pg_version = t.Pg_version
 }
 ret, _ := json.Marshal(data)
 w.Write(ret)
}

/*
功能描述：获回节点类型、状态及版本信息，值直接付给row属性

先用数据库参数连接获取 节点类型、状态及版本信息 ，如果数据库服务获取失败再用pg_controldata获取

参数说明：
row -- *Row指针

返回值说明： 无
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

 //连接db
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
    row.Pg_version = "获取版本号出错" + err.Error()
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
  stdout, stderr := ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
  if stderr != "" {
   row.Service_status = "无法获得节点状态，详情" + stderr
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
   go ssh_run_chan(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd, status_out_chan)
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
   //需要检查port是否已经存在,存在表示运行中,pg_basebackup复制后,如果没启动过,则这个值是"in production"
   cmd = "netstat -tunlp |grep " + fmt.Sprintf("%d", row.Pg_port)
   status_out_chan := make(chan Stdout_and_stderr)
   go ssh_run_chan(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd, status_out_chan)
   //需要检查recovery.conf是否已经存在,存在表示是备节点
   cmd = "ls " + row.Pg_data + "recovery.conf"
   type_out_chan := make(chan Stdout_and_stderr)
   go ssh_run_chan(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd, type_out_chan)
   status_out := <-status_out_chan
   fmt.Println("status_out:")
   fmt.Println(status_out)
   if status_out.Stdout != "" {
    row.Service_status = "运行中"
   } else {
    row.Service_status = "服务停止"
   }
   type_out := <-type_out_chan
   if type_out.Stdout != "" {
    row.Service_status = "备节点"
   } else {
    row.Service_status = "主节点"
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

 //连接db
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
        node_name, host,
        ssh_port, ssh_user,
        ssh_password, pg_bin,
        pg_data, pg_log,
  pg_port,
        pg_database, pg_user,
        pg_password, remark,
        master_vip, master_vip_networkcard,
        slave_vip, slave_vip_networkcard,    
        bind_vip_user, bind_vip_password
    ) 
    VALUES
    (   
        $1, $2,
        $3, $4,
        $5, $6,
        $7, $8,
        $9,
  $10, $11,
  $12, $13,
  $14, $15,
  $16, $17,
  $18, $19
    ) returning id    
    `
 rows, err = conn.Query(sql,
  r.FormValue("node_name"), r.FormValue("host"),
  r.FormValue("ssh_port"), r.FormValue("ssh_user"),
  r.FormValue("ssh_password"), r.FormValue("pg_bin"),
  r.FormValue("pg_data"), r.FormValue("pg_log"),
  r.FormValue("pg_port"),
  r.FormValue("pg_database"), r.FormValue("pg_user"),
  r.FormValue("pg_password"), r.FormValue("remark"),
  r.FormValue("master_vip"), r.FormValue("master_vip_networkcard"),
  r.FormValue("slave_vip"), r.FormValue("slave_vip_networkcard"),
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

 //连接db
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
        ssh_user=$4, ssh_password=$5,
        pg_bin=$6, pg_data=$7,
        pg_port=$8, pg_database=$9,
        pg_user=$10, pg_password=$11,
        remark=$12, pg_log=$13,
        master_vip=$14, master_vip_networkcard=$15,
        slave_vip=$16, slave_vip_networkcard=$17,    
        bind_vip_user=$18, bind_vip_password=$19 
    WHERE 
        id=$20
    `
 _, err = conn.Exec(sql,
  r.FormValue("node_name"),
  r.FormValue("host"), r.FormValue("ssh_port"),
  r.FormValue("ssh_user"), r.FormValue("ssh_password"),
  r.FormValue("pg_bin"), r.FormValue("pg_data"),
  r.FormValue("pg_port"), r.FormValue("pg_database"),
  r.FormValue("pg_user"), r.FormValue("pg_password"),
  r.FormValue("remark"), r.FormValue("pg_log"),
  r.FormValue("master_vip"), r.FormValue("master_vip_networkcard"),
  r.FormValue("slave_vip"), r.FormValue("slave_vip_networkcard"),
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

 //连接db
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

 if act == "reload" {
  //reload获取postgresql主进程产生的日志
  cmd = "ls " + row.Pg_log + " '-rt'"
  stdout, stderr = ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
  if stderr != "" {
   row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + stderr
   return row
  }
  lines = strings.Split(stdout, "\n")
  filename = lines[len(lines)-2]
  cmd = "test -f " + row.Pg_data + "postmaster.pid && pid=`head -1  " + row.Pg_data + "postmaster.pid" + " `;test -f " + row.Pg_data + "postmaster.pid  && cat " + row.Pg_log + filename + " | grep $pid"
  stdout, stderr = ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
  if stderr != "" {
   row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：" + stderr
   return row
  }
  before_lines = strings.Split(stdout, "\n")
 }

 //ssh主机并执行相应的命令
 cmd = row.Pg_bin + "pg_ctl " + act + " -D " + row.Pg_data + mode + " > " + row.Pg_data + username + "_logfile.txt;cat " + row.Pg_data + username + "_logfile.txt"
 stdout, stderr = ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)

 if act == "start" || act == "restart" {
  time.Sleep(1 * time.Second)
 }

 //重新获取节点的状态
 row_chan := make(chan Row)
 go getnode_type_and_status(row_chan, row)
 row = <-row_chan

 if stderr != "" && (stdout == "" || act != "restart") {
  row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：" + stderr
  return row
 }

 //如果是start或者restart操作的并且操作后节点的状态处于"服务停止"
 if row.Service_status == "服务停止" && (act == "start" || act == "restart") {
  //需要判断是否有参数配置出错或者资源冲突导致数据库关闭
  cmd = "cat " + row.Pg_data + username + "_logfile.txt"
  logstdout, logstderr := ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
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
   stdout, stderr = ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
   if stderr != "" {
    row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + stderr
    return row
   }
   lines = strings.Split(stdout, "\n")
   filename = lines[len(lines)-2]

   cmd = "cat " + row.Pg_log + filename
   stdout, stderr = ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
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
   logstdout, logstderr := ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
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
  logstdout, logstderr := ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
  if logstderr != "" {
   row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + logstderr
   return row
  }
  if logstdout != "" {
   row.Return_msg = "执行 [ " + act + " ] 失败，node_id为 [ " + fmt.Sprintf("%d", row.Id) + " ] ,详情：\n" + logstdout
   return row
  }
 }

 //如果是reload则需要去检查日志文件
 if act == "reload" {
  //reload获取postgresql主进程产生的日志
  cmd = "test -f " + row.Pg_data + "postmaster.pid && pid=`head -1  " + row.Pg_data + "postmaster.pid" + " `;test -f " + row.Pg_data + "postmaster.pid  && cat " + row.Pg_log + filename + " | grep $pid"
  logstdout, logstderr := ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
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
 stdout, stderr := ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
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
功能描述：参数配置--提交参数,提交后可以只保存,可能reload,也可能restart

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
 if r.FormValue("act") != "save" && r.FormValue("act") != "reload" && r.FormValue("act") != "restart" {
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

 parameter_file_name := row.Pg_data + r.FormValue("parameter_file_name")
 cmd := "cp " + parameter_file_name + " " + parameter_file_name + ".pgclusteradmin.bak" + ";echo \"" + r.FormValue("parameter_file_contents") + "\" > " + parameter_file_name
 _, stderr := ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
 if stderr != "" {
  error_msg = "保存配置文件内容出错,详情：" + stderr
  OutputJson(w, "FAIL", error_msg, 0)
  go write_log(remote_ip, modlename, username, "Error", error_msg)
  return
 }
 logcontent := "切换成功\nnode_id [ " + r.FormValue("id") + " ]\n参数文件[ " + r.FormValue("parameter_file_name") + " ]\n写入内容 [ " + r.FormValue("parameter_file_contents") + " ]"
 if r.FormValue("act") == "save" {
  OutputJson(w, "SUCCESS", "执行成功！", 0)
  go write_log(remote_ip, modlename, username, "Log,", logcontent)
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
 //判断绑定操作用户密码是否为空
 if r.FormValue("bind_vip_password") == "" {
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

 //如果绑定vip,则需要做一些检查工作
 cmd := ""
 if r.FormValue("act") == "bind" {
  cmd = "ping " + r.FormValue("vip") + " -c 3 | grep 'ttl'"
 } else {
  cmd = "cmdpath=`which 'ip'`;$cmdpath a |grep '" + r.FormValue("vip") + "'|grep '" + r.FormValue("vip_networkcard") + "'"
 }
 stdout, stderr := ssh_run(r.FormValue("bind_vip_user"), r.FormValue("bind_vip_password"), row.Host, row.Ssh_port, cmd)
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
 stdout, stderr = ssh_run(r.FormValue("bind_vip_user"), r.FormValue("bind_vip_password"), row.Host, row.Ssh_port, cmd)
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
 //判断绑定操作用户名是否为空
 if r.FormValue("vip") != "" && r.FormValue("bind_vip_user") == "" {
  error_msg = "绑定操作用户名不能为空"
  OutputJson(w, "FAIL", error_msg, 0)
  go write_log(remote_ip, modlename, username, "Error", error_msg)
  return
 }
 //判断绑定操作用户密码是否为空
 if r.FormValue("vip") != "" && r.FormValue("bind_vip_password") == "" {
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
  stdout, stderr := ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
  if stderr != "" {
   error_msg = "检查要绑定的VIP[" + r.FormValue("vip") + "]是否已经在本机上绑定出错，详情：" + stderr
   OutputJson(w, "FAIL", error_msg, 0)
   go write_log(remote_ip, modlename, username, "Error", error_msg)
   return
  }
  //没有在本机上绑定需要判断是否已经在其它机器上已经绑定
  if stdout == "" {
   cmd = "ping " + r.FormValue("vip") + " -c 3 | grep 'ttl'"
   stdout, stderr = ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
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
 _, stderr = ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
 if stderr != "" {
  error_msg = "备机唤醒出错,详情:" + stderr
  OutputJson(w, "FAIL", error_msg, 0)
  go write_log(remote_ip, modlename, username, "Error", error_msg)
  return
 }

 //执行绑定VIP操作
 if r.FormValue("vip") != "" && bindvip == 1 {
  cmd = "cmdpath=`which 'ifconfig'`;$cmdpath '" + r.FormValue("vip_networkcard") + "' '" + r.FormValue("vip") + "'"
  _, stderr = ssh_run(r.FormValue("bind_vip_user"), r.FormValue("bind_vip_password"), row.Host, row.Ssh_port, cmd)
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
 //连接db
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
   stdout, stderr := ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
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
   _, stderr = ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
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
  go ssh_run_chan(r.FormValue("master_bind_user"), r.FormValue("master_bind_password"), master_row.Host, master_row.Ssh_port, cmd, master_unbind_vip_chan)
 }

 //如果备节点需要解绑vip，则需要做一些检查工作
 slave_unbind_vip_chan := make(chan Stdout_and_stderr)
 if r.FormValue("slave_unbind_vip") != "" {
  //判断解绑vip是否存在
  cmd := "cmdpath=`which 'ip'`;$cmdpath a |grep '" + r.FormValue("slave_unbind_vip") + "'|grep '" + r.FormValue("slave_unbind_vip_networkcard") + "'"
  go ssh_run_chan(r.FormValue("slave_bind_user"), r.FormValue("slave_bind_password"), slave_row.Host, slave_row.Ssh_port, cmd, slave_unbind_vip_chan)
 }

 //如果主节点需要绑定vip,并且要绑定的vip不是备节点要解绑的Vip，则需要做一些检查工作
 master_bind_vip_chan := make(chan Stdout_and_stderr)
 if r.FormValue("master_bind_vip") != "" && r.FormValue("master_bind_vip") != r.FormValue("slave_unbind_vip") {
  cmd := "ping " + r.FormValue("master_bind_vip") + " -c 3 | grep 'ttl'"
  go ssh_run_chan(r.FormValue("master_bind_user"), r.FormValue("master_bind_password"), master_row.Host, master_row.Ssh_port, cmd, master_bind_vip_chan)
 }

 //如果备节点需要绑定vip,并且要绑定的vip不是主节点要解绑的Vip，则需要做一些检查工作
 slave_bind_vip_chan := make(chan Stdout_and_stderr)
 if r.FormValue("slave_bind_vip") != "" && r.FormValue("slave_bind_vip") != r.FormValue("master_unbind_vip") {
  cmd := "ping " + r.FormValue("slave_bind_vip") + " -c 3 | grep 'ttl'"
  go ssh_run_chan(r.FormValue("slave_bind_user"), r.FormValue("slave_bind_password"), slave_row.Host, slave_row.Ssh_port, cmd, slave_bind_vip_chan)
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
  go ssh_run_chan(r.FormValue("master_bind_user"), r.FormValue("master_bind_password"), master_row.Host, master_row.Ssh_port, cmd, master_unbind_vip_chan)
 }

 //切换前备节点解绑vip
 if r.FormValue("slave_unbind_vip") != "" {
  //异步执行解绑vip工作
  cmd := "cmdpath=`which 'ip'`;$cmdpath addr del '" + r.FormValue("slave_unbind_vip") + "/24' dev '" + r.FormValue("slave_unbind_vip_networkcard") + "'"
  go ssh_run_chan(r.FormValue("slave_bind_user"), r.FormValue("slave_bind_password"), slave_row.Host, slave_row.Ssh_port, cmd, slave_unbind_vip_chan)
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
 _, stderr := ssh_run(master_row.Ssh_user, master_row.Ssh_password, master_row.Host, master_row.Ssh_port, cmd)

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
 _, stderr = ssh_run(slave_row.Ssh_user, slave_row.Ssh_password, slave_row.Host, slave_row.Ssh_port, cmd)

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
 _, stderr = ssh_run(master_row.Ssh_user, master_row.Ssh_password, master_row.Host, master_row.Ssh_port, cmd)

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
  go ssh_run_chan(r.FormValue("master_bind_user"), r.FormValue("master_bind_password"), master_row.Host, master_row.Ssh_port, cmd, master_bind_vip_chan)
 }

 //切换后原来的备节点（现在变成主节点了）需要绑定vip
 if r.FormValue("slave_bind_vip") != "" {
  //异步绑定vip
  cmd := "cmdpath=`which 'ifconfig'`;$cmdpath '" + r.FormValue("slave_bind_vip_networkcard") + "' '" + r.FormValue("slave_bind_vip") + "'"
  go ssh_run_chan(r.FormValue("slave_bind_user"), r.FormValue("slave_bind_password"), slave_row.Host, slave_row.Ssh_port, cmd, slave_bind_vip_chan)
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
 go ssh_run_chan(master_row.Ssh_user, master_row.Ssh_password, master_row.Host, master_row.Ssh_port, cmd, master_out_chan)

 //异步检查备节点
 cmd = slave_row.Pg_bin + "pg_controldata " + slave_row.Pg_data + ";cat " + slave_row.Pg_data + "recovery.conf"
 slave_out_chan := make(chan Stdout_and_stderr)
 go ssh_run_chan(slave_row.Ssh_user, slave_row.Ssh_password, slave_row.Host, slave_row.Ssh_port, cmd, slave_out_chan)

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
 //获取ip绑定情况
 cmd := "cmdpath=`which 'ip'`;$cmdpath a"
 stdout, stderr := ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
 out.Stdout = stdout
 out.Stderr = stderr
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
 //连接db
 var row Row
 row.Return_code = "SUCCESS"
 row.Return_msg = ""
 var conn *pgx.Conn
 conn, err := pgx.Connect(extractConfig())
 if err != nil {
  row.Return_code = "FAIL"
  row.Return_msg = "连接db失败，详情：" + err.Error()
  s <- row
  return
 }
 defer conn.Close()

 //查询返回节点信息
 sql := `
    SELECT 
        id,node_name,
        createtime::text,host,
        ssh_port,ssh_user,
        ssh_password,pg_bin,
        pg_data,pg_log,
  pg_port,pg_database,
  pg_user,pg_password,
        master_vip,master_vip_networkcard,
        slave_vip,slave_vip_networkcard,    
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
   &row.Ssh_port, &row.Ssh_user,
   &row.Ssh_password, &row.Pg_bin,
   &row.Pg_data, &row.Pg_log,
   &row.Pg_port, &row.Pg_database,
   &row.Pg_user, &row.Pg_password,
   &row.Master_vip, &row.Master_vip_networkcard,
   &row.Slave_vip, &row.Slave_vip_networkcard,
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
 _, stderr := ssh_run(row.Ssh_user, row.Ssh_password, row.Host, row.Ssh_port, cmd)
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
user      --ssh登录用户名
password  --ssh登录用户密码
host      --ssh访问主机ip或host
port      --ssh服务的port

返回值说明：
session   --ssh.Session连接指针
error     --error对象
*/

func ssh_connect(user string, password string, host string, port int) (*ssh.Session, error) {
 var (
  auth         []ssh.AuthMethod
  addr         string
  clientConfig *ssh.ClientConfig
  client       *ssh.Client
  session      *ssh.Session
  err          error
 )

 auth = make([]ssh.AuthMethod, 0)
 auth = append(auth, ssh.Password(password))

 clientConfig = &ssh.ClientConfig{
  User:    user,
  Auth:    auth,
  Timeout: 30 * time.Second,
 }

 addr = fmt.Sprintf("%s:%d", host, port)

 if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
  return nil, err
 }

 if session, err = client.NewSession(); err != nil {
  return nil, err
 }

 return session, nil
}

/*
功能描述：ssh上主机并执行命令，返回执行的结果及错误

参数说明：
user      --ssh登录用户名
password  --ssh登录用户密码
host      --ssh访问主机ip或host
port      --ssh服务的port
cmd       --要执行的脚本

返回值说明：
return_stdout  --返回执行返回的输出信息
return_stderr  --返回执行返回的出错信息
*/

func ssh_run(user string, password string, host string, port int, cmd string) (return_stdout string, return_stderr string) {
 //ssh连接
 session, err := ssh_connect(user, password, host, port)
 if err != nil {
  return "", err.Error()
 }

 var stdout bytes.Buffer
 var stderr bytes.Buffer
 session.Stdout = &stdout
 session.Stderr = &stderr

 session.Run(cmd)
 session.Close()

 return stdout.String(), stderr.String()
}

/*
功能描述：异步--ssh上主机并执行命令，返回执行的结果及错误

参数说明：
user      --ssh登录用户名
password  --ssh登录用户密码
host      --ssh访问主机ip或host
port      --ssh服务的port
cmd       --要执行的脚本

返回值说明：
s -- 结构体Stdout_and_stderr变量
*/

func ssh_run_chan(user string, password string, host string, port int, cmd string, s chan Stdout_and_stderr) {
 //定义返回的struct
 var out Stdout_and_stderr
 //ssh连接
 session, err := ssh_connect(user, password, host, port)
 if err != nil {
  out.Stdout = ""
  out.Stderr = err.Error()
  s <- out
  return
 }

 var stdout bytes.Buffer
 var stderr bytes.Buffer
 session.Stdout = &stdout
 session.Stderr = &stderr

 session.Run(cmd)
 session.Close()

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
 //连接db，保存日志
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
  if v <= 0 || v > 255 {
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

 config.Host = "192.168.1.10"  //数据库主机host或ip
 config.User = "postgres"      //连接用户
 config.Password = "pgsql"     //用户密码
 config.Database = "pgcluster" //连接数据库名
 config.Port = 5432            //端口号

 return config
}

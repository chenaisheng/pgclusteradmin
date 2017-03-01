$(document).ready(function()
{     
     //ip检查，是否为空检查
     $.extend($.fn.validatebox.defaults.rules,{
         isip: {// 验证日期
                    validator: function (value) {
                        //格式yyyy-MM-dd或yyyy-M-d
                        return isIP (value);    
                    },
                    message: '清输入正确的ip地址，如192.168.1.11'
         },
         bind_unbind_vip_equal: {
                    validator: function(value,param){
                    ip = $(param[0]).textbox('getValue');  
                    if(ip==value)
                        {                                    
                            return false;
                        }
                    else
                        {   
                            return true;
                        }
                    },
                    message: '解绑和绑定的vip不能相同'
         },
         master_slave_vip_equal: {
                    validator: function(value,param){
                    val = $(param[0]).textbox('getValue');  
                    if(val==value)
                        {                                    
                            return false;
                        }
                    else
                        {   
                            return true;
                        }
                    },
                    message: '主备要绑定或解绑的vip不能相同'
         },
         password_equal: {
                    validator: function(value,param){
                    val = $(param[0]).textbox('getValue');  
                    if(val==value)
                        {                                    
                            return true;
                        }
                    else
                        {   
                            return false;
                        }
                    },
                    message: '要更新的密码不一致'
         }    
    });  
    function isIP(ip){   
        var re =  /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$/   
        return re.test(ip);   
    }   
    
});  
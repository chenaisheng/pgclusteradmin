package main

import (
   "net/http"
   "fmt"
   
)

func main() {
     //设置静态资源存入路径
     http.Handle("/", http.FileServer(http.Dir("./easyui/")))
     http.ListenAndServe(":10001", nil)
}
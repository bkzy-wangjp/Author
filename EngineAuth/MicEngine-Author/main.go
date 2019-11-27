package main

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	auth "github.com/bkzy-wangjp/Author/EngineAuth"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	var p_cnt, s_cnt int             //并发指标数量,串行指标数量
	var username, mcode, pswd string //用户名,机器码
	fmt.Println("北矿智云科技（北京）有限公司")
	fmt.Println("MicEngine软件授权码生成器")
	fmt.Println("版本:V1.0")
	fmt.Println("发布日期:2019年11月27日")

	ips := 0
	ipc := 0
	pserr := 3
	fmt.Printf("请输入密码->")
iptpswd:
	_, err := fmt.Scanf("%s", &pswd)
	if !strings.EqualFold(pswd, time.Now().Format("20060102")) {
		ips++
		if ips > 1 {
			pserr--
			if pserr < 1 {
				return
			}
			fmt.Printf("密码错误,还有%d次机会->", pserr)
			ips = 0
		}
		goto iptpswd
	}
	thismcode := auth.MachineCodeEncrypt() //本机机器码
	fmt.Println("本机机器码:", thismcode)
	fmt.Println("-----------------------开始授权码生成工作------------------------")
	fmt.Println("请依次输入:并发指标数量、串行指标数量、用户名和机器码,中间以空格分割,注意大小写敏感:")
inputloop:
	i, err := fmt.Scanf("%d %d %s %s", &p_cnt, &s_cnt, &username, &mcode)
	if i < 3 || err != nil {
		ipc++
		if ipc > 1 {
			fmt.Println("输入错误:", err.Error())
			fmt.Println("请依次输入:并发指标数量、串行指标数量、用户名和机器码,中间以空格分割,注意大小写敏感:")
			ipc = 0
		}
		goto inputloop
	}
	key, mac, ok := auth.MachineCodeDecrypt(mcode) //解码机器码,得到密钥和mca明文

	if ok {
		fmt.Printf("机器码密钥为%s,硬件串码为:%s\r", key, mac)

		authCode, _ := auth.AuthorizationCodeEncrypt(p_cnt, s_cnt, username, mcode) //生成授权串码
		fmt.Println("授权码为:", authCode)
		p, s, u, mc, _ := auth.AuthorizationCodeDecrypt(key, authCode) //授权码解码校验
		fmt.Println("授权解码校验:")
		fmt.Printf("并发指标授权数量:%d,串行指标授权数量:%d\r", p, s)
		fmt.Println("授权用户:", u)
		fmt.Println("系统盘信息:", key)
		fmt.Println("网卡MAC:", mc)
		ok := SaveAuthMsg(p_cnt, s_cnt, mcode, key, mac, username, authCode) //存储信息
		if ok {
			fmt.Println("授权信息保存成功!")
		} else {
			fmt.Println("授权信息保存失败!")
		}
	} else {
		fmt.Println("机器码非法,拒绝生成授权码,请重新输入！")
	}
	fmt.Println("------------分割线,请继续生成授权码,或者直接关闭----------------")
	fmt.Println("请依次输入:并发指标数量、串行指标数量、用户名和机器码,中间以空格分割,注意大小写敏感:")
	ipc = 0
	goto inputloop
}

func SaveAuthMsg(p_cnt, s_cnt int, mcode, key, mac, username, authCode string) bool {
	srcDbMsg := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8",
		"micetl",
		"Etl2bkzy",
		"rm-2zehm037lnj7rl64wo.mysql.rds.aliyuncs.com",
		"3306",
		"bkzy_auth")
	db, err := sql.Open("mysql", srcDbMsg)
	if err != nil {
		fmt.Println("打开数据失败", err.Error)
		return false
	}
	defer db.Close()
	//Begin函数内部会去获取连接
	tx, _ := db.Begin()
	sqlInsert := fmt.Sprintf("INSERT INTO %s(%s,%s,%s,%s,%s,%s,%s,%s) VALUES('%s','%s','%s','%s','%s',%d,%d,'%s')",
		"micengine",
		"DataTime",
		"MachineCode",
		"AuthCode",
		"SysDiskInfo",
		"NetMac",
		"parallel_indicator_auth",
		"serial_indicator_auth",
		"UserName",
		time.Now().Format("2006-01-02 15:04:05"),
		mcode, authCode, key, mac, p_cnt, s_cnt, username)
	//每次循环用的都是tx内部的连接，没有新建连接，效率高
	//fmt.Println("SQL:", sqlInsert)
	_, err = tx.Exec(sqlInsert)
	if err != nil {
		fmt.Println("数据存储失败", err.Error)
		return false
	}
	tx.Commit()
	return true
}

package main

import (
	"fmt"

	"github.com/bkzy-wangjp/Author"
)

func main() {

	//	fmt.Printf("开机时长:%s\n", Author.GetStartTime())
	//	fmt.Printf("当前用户:%s\n", Author.GetUserName())
	//	//fmt.Printf("当前系统:%s\n", runtime.GOOS)
	//	fmt.Printf("系统版本:%s\n", Author.GetSystemVersion())
	//	fmt.Printf("BIOS Info:%s\n", Author.GetBiosInfo())
	//	//fmt.Printf("Motherboard:\t%s\n", GetMotherboardInfo())

	//	fmt.Printf("CPU:\t%s\n", Author.GetCpuInfo())
	//	fmt.Printf("Memory:\t%s\n", Author.GetMemory())
	//	fmt.Printf("Disk:\t%v\n", Author.GetDiskInfo())
	/*---------------------------------------------------*/
	mc := Author.MachineCodeEncrypt()
	fmt.Println("机器码:", mc)
	authCode := Author.AuthorizationCodeEncrypt(128, "wangjunpeng", mc)
	fmt.Println("授权码:", authCode)
	cnt, username, mcode := Author.AuthorizationCheck(authCode)
	fmt.Println("授权解码:", cnt, username, mcode)

}

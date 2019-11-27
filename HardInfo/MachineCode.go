package Hardinfo

import (
	"bytes"
	"fmt"

	pkcs "github.com/bkzy-wangjp/Author/PKCS"

	"strings"

	"github.com/bkzy-wangjp/CRC16"
)

/*
功能：用网卡信息和硬盘信息生成机器码，并输出机器码
输入：密钥补充码
输出：机器码
*/
func MachineCodeEncrypt(keySupplementary string) string {
	dsk := GetDiskInfo() //GetMotherboardInfo() //C盘信息
	var disk0total string
	if len(dsk) > 0 {
		disk0total = fmt.Sprintf("%s%d", dsk[0].Path, dsk[0].Total) //盘符和总空间组成密钥
	} else {
		disk0total = keySupplementary
	}
	NetInfo := GetIntfs() //网卡信息
	var mac string
	if len(NetInfo) > 0 {
		mac = NetInfo[0].MacAddress
	} else {
		mac = ""
	}

	var str bytes.Buffer
	str.WriteString(pkcs.GetReversalStr(disk0total))
	str.WriteString(pkcs.GetReversalStr(strings.Replace(mac, ":", "", -1)))

	return crc16.StringAndCrcSum(str.String())
}

/*
功能：机器码解码
输入：机器码
输出：密钥，密文，密文的crc校验结果
*/
func MachineCodeDecrypt(mc string) (key, mac string, ok bool) {
	mcode, crcok := crc16.StringCheckCRC(mc)
	ok = crcok
	if crcok {
		key = string([]byte(mcode)[:len(mcode)-12]) //获取密钥
		mac = string([]byte(mcode)[len(mcode)-12:]) //获取密文
	} else {
		key = ""
		mac = ""
	}
	return pkcs.GetReversalStr(key), pkcs.GetReversalStr(mac), ok
}

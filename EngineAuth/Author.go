package EngineAuth

import (
	"encoding/base64"
	"fmt"

	pkcs "github.com/bkzy-wangjp/Author/PKCS"
	hard "github.com/bkzy-wangjp/Author/hardinfo"

	"strconv"
	"strings"

	"github.com/bkzy-wangjp/CRC16"
)

var (
	keySupplementary = []byte("micEngine@bkzy.ltd*") //密钥补充码
)

/*
功能：授权码编码
输入：cnt:授权数量
	username:被授权用户名
	mcode:机器码
输出：string:授权码
	bool:机器码校验结果,true=成功,false=失败
时间：2019年11月27日
作者：wang_jp
*/
func AuthorizationCodeEncrypt(p_cnt, s_cnt int, username, mcode string) (string, bool) {
	//mb:密钥,待授权机器的系统盘信息; mac:密文,待授权机器的mac地址;
	mb, mac, ok := MachineCodeDecrypt(mcode) //机器码解码
	var auth string
	if ok {
		var key []byte
		if len(mb) < 16 { //如果密钥不够16位，用密钥补充码补充到16位
			for i := 0; len(mb) < 16; i++ {
				mb = fmt.Sprintf("%s%c", mb, keySupplementary[i])
			}
			key = append(key, []byte(mb)...)
		} else { //如果密钥大于16位,取前16位
			key = []byte(mb)[:16]
		}
		var code string
		//用授权数量的长度和用户名的长度的16进制，以及授权数量，用户名，mac地址组成编码
		code = fmt.Sprintf("%02x%02x%02x%d%d%s%s",
			len(strconv.Itoa(p_cnt)),
			len(strconv.Itoa(s_cnt)),
			len(username),
			p_cnt,
			s_cnt,
			username,
			mac)
		cc, err := pkcs.AesEncrypt([]byte(code), key) //加密
		if err != nil {
			panic(err)
		}
		auth = base64.StdEncoding.EncodeToString(cc) //
	} else {
		auth = ""
	}
	return crc16.StringAndCrcSum(auth), ok //添加crc校验码后输出
}

/*
功能：检查校验授权码
输入：authCode:授权码
输出：cnt:授权数量
	username:被授权用户名
	ok:校验结果,true=通过,false=不通过
时间：2019年11月27日
作者：wang_jp
*/
func AuthorizationCheck(authCode string) (p_cnt, s_cnt, r_cnt int, username string, ok bool) {
	ok = false
	dsk := hard.GetDiskInfo() //C盘信息
	var disk0total string
	if len(dsk) > 0 {
		disk0total = fmt.Sprintf("%s%d", dsk[0].Path, dsk[0].Total) //盘符和总空间组成密钥
	} else {
		disk0total = string(keySupplementary)
	}

	var mac string
	var checkok bool
	p_cnt, s_cnt, username, mac, checkok = AuthorizationCodeDecrypt(disk0total, authCode) //授权码解码
	r_cnt = s_cnt / 100
	if r_cnt < 50 {
		r_cnt = 50
	}
	ok = checkok
	if checkok { //授权码解码成功
		NetInfo := hard.GetIntfs()
		for _, v := range NetInfo {
			ok = strings.EqualFold(strings.ToLower(mac), strings.ToLower(strings.Replace(v.MacAddress, ":", "", -1))) && len(v.MacAddress) >= 12
			if ok {
				return p_cnt, s_cnt, r_cnt, username, ok
			}
		}
	}
	return p_cnt, s_cnt, r_cnt, username, ok
}

/*
功能：授权码解码
输入：keycode:密钥
	authCode:授权码
输出：cnt:授权数量
	username:被授权用户名
	mcode:从授权码中解析出来的被授权的机器码
	bool:授权码解码结果,true=成功,false=失败
时间：2019年11月27日
作者：wang_jp
*/
func AuthorizationCodeDecrypt(keycode, authCode string) (p_cnt, s_cnt int, username, mcode string, ok bool) {
	var key []byte
	if len(keycode) < 16 { //密钥必需为16位，如果密钥不够16位，用密钥补充码补充到16位
		k := keycode
		for i := 0; len(k) < 16; i++ {
			k = fmt.Sprintf("%s%c", k, keySupplementary[i])
		}
		key = append(key, []byte(k)...)
	} else { //如果密钥大于16位,取前16位
		key = []byte(keycode)[:16]
	}
	auth, crcok := crc16.StringCheckCRC(authCode) //CRC校验

	ok = crcok
	if crcok {
		if len(auth) < 12 { //授权码长度不能小于12，否则授权失败
			p_cnt = 0
			s_cnt = 0
			username = ""
			mcode = auth
			return p_cnt, s_cnt, username, mcode, false
		}
		bytesPass, err := base64.StdEncoding.DecodeString(auth) //解密

		if err != nil { //解密不成功,授权失败
			p_cnt = 0
			s_cnt = 0
			username = ""
			mcode = auth
			return p_cnt, s_cnt, username, mcode, false
		}
		tpass, err := pkcs.AesDecrypt(bytesPass, key) //解密
		if err != nil {                               //解密不成功,授权失败
			fmt.Println(err.Error())
			p_cnt = 0
			s_cnt = 0
			username = ""
			mcode = auth
			return p_cnt, s_cnt, username, mcode, false
		}

		p_cntl, err := strconv.ParseInt(string(tpass[:2]), 16, 64) //授权数量校验
		if err != nil {                                            //校验不成功,授权失败
			p_cnt = 0
			s_cnt = 0
			username = ""
			mcode = auth
			return p_cnt, s_cnt, username, mcode, false
		}
		s_cntl, err := strconv.ParseInt(string(tpass[2:4]), 16, 64) //授权数量校验
		if err != nil {                                             //校验不成功,授权失败
			p_cnt = 0
			s_cnt = 0
			username = ""
			mcode = auth
			return p_cnt, s_cnt, username, mcode, false
		}
		namel, err := strconv.ParseInt(string(tpass[4:6]), 16, 64) //用户名长度校验
		if err != nil {                                            //校验不成功,授权失败
			p_cnt = 0
			s_cnt = 0
			username = ""
			mcode = auth
			return p_cnt, s_cnt, username, mcode, false
		}
		p_cnt, err = strconv.Atoi(string(tpass[6 : p_cntl+6])) //获取授权数量
		if err != nil {                                        //授权数量获取不成功,授权失败
			p_cnt = 0
			s_cnt = 0
			username = ""
			mcode = auth
			return p_cnt, s_cnt, username, mcode, false
		}
		s_cnt, err = strconv.Atoi(string(tpass[p_cntl+6 : p_cntl+s_cntl+6])) //获取授权数量
		if err != nil {                                                      //授权数量获取不成功,授权失败
			p_cnt = 0
			s_cnt = 0
			username = ""
			mcode = auth
			return p_cnt, s_cnt, username, mcode, false
		}
		username = string(tpass[p_cntl+s_cntl+6 : p_cntl+s_cntl+namel+6]) //获取用户名
		mcode = string(tpass[p_cntl+s_cntl+namel+6:])                     //剩下的是机器码(Mac)信息
	} else { //CRC校验不成功，授权失败
		p_cnt = 0
		s_cnt = 0
		username = ""
		mcode = auth
		return p_cnt, s_cnt, username, mcode, false
	}
	ok = crcok
	return p_cnt, s_cnt, username, mcode, ok
}

/*
功能：用网卡信息和硬盘信息生成机器码，并输出机器码
输出：机器码
*/
func MachineCodeEncrypt() string {
	return hard.MachineCodeEncrypt(string(keySupplementary))
}

/*
功能：机器码解码
输入：机器码
输出：密钥，密文，密文的crc校验结果
*/
func MachineCodeDecrypt(mcode string) (string, string, bool) {
	return hard.MachineCodeDecrypt(mcode)
}

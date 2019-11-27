package Author

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	hard "github.com/bkzy-wangjp/Author/hardinfo"

	"strconv"
	"strings"

	"github.com/bkzy-wangjp/CRC16"
)

var (
	keySupplementary = []byte("micetl@bkzy.ltd*") //密钥补充码
)

/*授权检查*/
func AuthorizationCheck(authCode string) (cnt int, username string, ok bool) {
	ok = false
	dsk := hard.GetDiskInfo() //GetMotherboardInfo() //C盘信息
	var disk0total string
	if len(dsk) > 0 {
		disk0total = fmt.Sprintf("%s%d", dsk[0].Path, dsk[0].Total) //盘符和总空间组成密钥
	} else {
		disk0total = string(keySupplementary)
	}

	var mac string
	var checkok bool
	cnt, username, mac, checkok = AuthorizationCodeDecrypt(disk0total, authCode) //授权码解码
	ok = checkok
	if checkok {
		NetInfo := hard.GetIntfs()
		for _, v := range NetInfo {
			ok = strings.EqualFold(strings.ToLower(mac), strings.ToLower(strings.Replace(v.MacAddress, ":", "", -1))) && len(v.MacAddress) >= 12
			if ok {
				return cnt, username, ok
			}
		}
	}
	return cnt, username, ok
}

/*授权码编码*/
func AuthorizationCodeEncrypt(cnt int, username, mcode string) (string, bool) {
	mb, mac, ok := MachineCodeDecrypt(mcode) //机器码解码
	var auth string
	if ok {
		var key []byte
		if len(mb) < 16 {
			for i := 0; len(mb) < 16; i++ {
				mb = fmt.Sprintf("%s%c", mb, keySupplementary[i])
			}
			key = append(key, []byte(mb)...)
		} else {
			key = []byte(mb)[:16]
		}
		var code string
		code = fmt.Sprintf("%02x%02x%d%s%s",
			len(strconv.Itoa(cnt)),
			len(username),
			cnt,
			username,
			mac)
		cc, err := AesEncrypt([]byte(code), key)
		if err != nil {
			panic(err)
		}
		auth = base64.StdEncoding.EncodeToString(cc)
	} else {
		auth = ""
	}
	return crc16.StringAndCrcSum(auth), ok
}

/*授权码解码*/
func AuthorizationCodeDecrypt(keycode, authCode string) (cnt int, username, mcode string, ok bool) {
	var key []byte
	if len(keycode) < 16 { //密钥必需为16位
		k := keycode
		for i := 0; len(k) < 16; i++ {
			k = fmt.Sprintf("%s%c", k, keySupplementary[i])
		}
		key = append(key, []byte(k)...)
	} else {
		key = []byte(keycode)[:16]
	}
	auth, crcok := crc16.StringCheckCRC(authCode) //CRC校验

	ok = crcok
	if crcok {
		if len(auth) < 12 { //长度不能小于12
			cnt = 0
			username = ""
			mcode = auth
			return cnt, username, mcode, false
		}
		bytesPass, err := base64.StdEncoding.DecodeString(auth) //解密

		if err != nil {
			cnt = 0
			username = ""
			mcode = auth
			return cnt, username, mcode, false
		}
		tpass, err := AesDecrypt(bytesPass, key)
		if err != nil {
			fmt.Println(err.Error())
			cnt = 0
			username = ""
			mcode = auth
			return cnt, username, mcode, false
		}

		cntl, err := strconv.ParseInt(string(tpass[:2]), 16, 64)
		if err != nil {
			cnt = 0
			username = ""
			mcode = auth
			return cnt, username, mcode, false
		}
		namel, err := strconv.ParseInt(string(tpass[2:4]), 16, 64)
		if err != nil {
			cnt = 0
			username = ""
			mcode = auth
			return cnt, username, mcode, false
		}
		cnt, err = strconv.Atoi(string(tpass[4 : cntl+4]))
		if err != nil {
			cnt = 0
			username = ""
			mcode = auth
			return cnt, username, mcode, false
		}
		username = string(tpass[cntl+4 : cntl+namel+4])
		mcode = string(tpass[cntl+namel+4:])
	} else {
		cnt = 0
		username = ""
		mcode = auth
		return cnt, username, mcode, false
	}
	ok = crcok
	return cnt, username, mcode, ok
}

/*机器码编码*/
func MachineCodeEncrypt() string {
	dsk := hard.GetDiskInfo() //GetMotherboardInfo() //C盘信息
	var disk0total string
	if len(dsk) > 0 {
		disk0total = fmt.Sprintf("%s%d", dsk[0].Path, dsk[0].Total) //盘符和总空间组成密钥
	} else {
		disk0total = string(keySupplementary)
	}
	NetInfo := hard.GetIntfs() //网卡信息
	var mac string
	if len(NetInfo) > 0 {
		mac = NetInfo[0].MacAddress
	} else {
		mac = ""
	}

	var str bytes.Buffer
	str.WriteString(getReversalStr(disk0total))
	str.WriteString(getReversalStr(strings.Replace(mac, ":", "", -1)))

	return crc16.StringAndCrcSum(str.String())
}

/*机器码解码*/
func MachineCodeDecrypt(mc string) (key, mac string, ok bool) {
	mcode, crcok := crc16.StringCheckCRC(mc)
	ok = crcok
	if crcok {
		key = string([]byte(mcode)[:len(mcode)-12]) //获取密钥
		mac = string([]byte(mcode)[len(mcode)-12:]) //获取密钥
	} else {
		key = ""
		mac = ""
	}
	return getReversalStr(key), getReversalStr(mac), ok
}

/*字符串翻转*/
func getReversalStr(src string) string {
	var dst []byte
	for _, b := range []byte(src) {
		dst = append(dst, 170-b)
	}
	return string(dst)
}

/*加密解密算法*/
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	//限制范围，否则有可能超过length或者小于0
	m := length - unpadding
	if m <= 0 || m > length {
		m = length
	}
	return origData[:m]
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

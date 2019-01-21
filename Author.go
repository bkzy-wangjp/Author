package Author

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net"

	//"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/StackExchange/wmi"
	//termbox "github.com/nsf/termbox-go"
)

var (
	advapi           = syscall.NewLazyDLL("Advapi32.dll")
	kernel           = syscall.NewLazyDLL("Kernel32.dll")
	keySupplementary = []byte("micetl@bkzy.ltd*") //密钥补充码
)

//func init() {
//	if err := termbox.Init(); err != nil {
//		panic(err)
//	}
//	termbox.SetCursor(0, 0)
//	termbox.HideCursor()
//}

//func Pause() {
//	fmt.Println("请按任意键继续...")
//	defer termbox.Close()
//Loop:
//	for {
//		switch ev := termbox.PollEvent(); ev.Type {
//		case termbox.EventKey:
//			break Loop
//		}
//	}
//}

/*授权检查*/
func AuthorizationCheck(authCode string) (cnt int, username string, ok bool) {
	ok = false
	Metherboard := GetMotherboardInfo() //主板型号
	var mac string
	cnt, username, mac = AuthorizationCodeDecrypt(Metherboard, authCode) //授权码解码
	NetInfo := GetIntfs()
	for _, v := range NetInfo {
		ok = strings.EqualFold(strings.ToLower(mac), strings.ToLower(strings.Replace(v.MacAddress, ":", "", -1))) && len(v.MacAddress) >= 12
		if ok {
			return cnt, username, ok
		}
	}
	return cnt, username, ok
}

/*授权码编码*/
func AuthorizationCodeEncrypt(cnt int, username, mcode string) string {
	mb, mac := MachineCodeDecrypt(mcode) //机器码解码
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
	return base64.StdEncoding.EncodeToString(cc)
}

/*授权码解码*/
func AuthorizationCodeDecrypt(keycode, authCode string) (cnt int, username, mcode string) {
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
	if len(authCode) < 12 {
		cnt = 0
		username = ""
		mcode = authCode
		return cnt, username, mcode
	}
	bytesPass, err := base64.StdEncoding.DecodeString(authCode) //解密
	if err != nil {
		cnt = 0
		username = ""
		mcode = authCode
		return cnt, username, mcode
	}
	tpass, err := AesDecrypt(bytesPass, key)
	if err != nil {
		fmt.Println(err.Error())
		cnt = 0
		username = ""
		mcode = authCode
		return cnt, username, mcode
	}

	cntl, err := strconv.ParseInt(string(tpass[:2]), 16, 64)
	if err != nil {
		cnt = 0
		username = ""
		mcode = authCode
		return cnt, username, mcode
	}
	namel, err := strconv.ParseInt(string(tpass[2:4]), 16, 64)
	if err != nil {
		cnt = 0
		username = ""
		mcode = authCode
		return cnt, username, mcode
	}
	cnt, err = strconv.Atoi(string(tpass[4 : cntl+4]))
	if err != nil {
		cnt = 0
		username = ""
		mcode = authCode
		return cnt, username, mcode
	}
	username = string(tpass[cntl+4 : cntl+namel+4])
	mcode = string(tpass[cntl+namel+4:])
	return cnt, username, mcode
}

/*机器码编码*/
func MachineCodeEncrypt() string {
	mb := GetMotherboardInfo() //主板型号
	NetInfo := GetIntfs()      //网卡信息
	mac := NetInfo[0].MacAddress

	var str bytes.Buffer
	str.WriteString(getReversalStr(mb))
	str.WriteString(getReversalStr(strings.Replace(mac, ":", "", -1)))
	return str.String()
}

/*机器码解码*/
func MachineCodeDecrypt(mc string) (key, mac string) {
	key = string([]byte(mc)[:len(mc)-12]) //获取密钥
	mac = string([]byte(mc)[len(mc)-12:]) //获取密钥
	return getReversalStr(key), getReversalStr(mac)
}

/*字符串翻转*/
func getReversalStr(src string) string {
	var dst []byte
	for _, b := range []byte(src) {
		dst = append(dst, 170-b)
	}
	return string(dst)
}

//开机时间
func GetStartTime() string {
	GetTickCount := kernel.NewProc("GetTickCount")
	r, _, _ := GetTickCount.Call()
	if r == 0 {
		return ""
	}
	ms := time.Duration(r * 1000 * 1000)
	return ms.String()
}

//当前用户名
func GetUserName() string {
	var size uint32 = 128
	var buffer = make([]uint16, size)
	user := syscall.StringToUTF16Ptr("USERNAME")
	domain := syscall.StringToUTF16Ptr("USERDOMAIN")
	r, err := syscall.GetEnvironmentVariable(user, &buffer[0], size)
	if err != nil {
		return ""
	}
	buffer[r] = '@'
	old := r + 1
	if old >= size {
		return syscall.UTF16ToString(buffer[:r])
	}
	r, err = syscall.GetEnvironmentVariable(domain, &buffer[old], size-old)
	return syscall.UTF16ToString(buffer[:old+r])
}

//系统版本
func GetSystemVersion() string {
	version, err := syscall.GetVersion()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d.%d (%d)", byte(version), uint8(version>>8), version>>16)
}

type diskusage struct {
	Path  string `json:"path"`
	Total uint64 `json:"total"`
	Free  uint64 `json:"free"`
}

func usage(getDiskFreeSpaceExW *syscall.LazyProc, path string) (diskusage, error) {
	lpFreeBytesAvailable := int64(0)
	var info = diskusage{Path: path}
	diskret, _, err := getDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(info.Path))),
		uintptr(unsafe.Pointer(&lpFreeBytesAvailable)),
		uintptr(unsafe.Pointer(&(info.Total))),
		uintptr(unsafe.Pointer(&(info.Free))))
	if diskret != 0 {
		err = nil
	}
	return info, err
}

//硬盘信息
func GetDiskInfo() (infos []diskusage) {
	GetLogicalDriveStringsW := kernel.NewProc("GetLogicalDriveStringsW")
	GetDiskFreeSpaceExW := kernel.NewProc("GetDiskFreeSpaceExW")
	lpBuffer := make([]byte, 254)
	diskret, _, _ := GetLogicalDriveStringsW.Call(
		uintptr(len(lpBuffer)),
		uintptr(unsafe.Pointer(&lpBuffer[0])))
	if diskret == 0 {
		return
	}
	for _, v := range lpBuffer {
		if v >= 65 && v <= 90 {
			path := string(v) + ":"
			if path == "A:" || path == "B:" {
				continue
			}
			info, err := usage(GetDiskFreeSpaceExW, string(v)+":")
			if err != nil {
				continue
			}
			infos = append(infos, info)
		}
	}
	return infos
}

//CPU信息
//简单的获取方法fmt.Sprintf("Num:%d Arch:%s\n", runtime.NumCPU(), runtime.GOARCH)
func GetCpuInfo() string {
	var size uint32 = 128
	var buffer = make([]uint16, size)
	var index = uint32(copy(buffer, syscall.StringToUTF16("Num:")) - 1)
	nums := syscall.StringToUTF16Ptr("NUMBER_OF_PROCESSORS")
	arch := syscall.StringToUTF16Ptr("PROCESSOR_ARCHITECTURE")
	r, err := syscall.GetEnvironmentVariable(nums, &buffer[index], size-index)
	if err != nil {
		return ""
	}
	index += r
	index += uint32(copy(buffer[index:], syscall.StringToUTF16(" Arch:")) - 1)
	r, err = syscall.GetEnvironmentVariable(arch, &buffer[index], size-index)
	if err != nil {
		return syscall.UTF16ToString(buffer[:index])
	}
	index += r
	return syscall.UTF16ToString(buffer[:index+r])
}

type memoryStatusEx struct {
	cbSize                  uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64 // in bytes
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

//内存信息
func GetMemory() string {
	GlobalMemoryStatusEx := kernel.NewProc("GlobalMemoryStatusEx")
	var memInfo memoryStatusEx
	memInfo.cbSize = uint32(unsafe.Sizeof(memInfo))
	mem, _, _ := GlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memInfo)))
	if mem == 0 {
		return ""
	}
	return fmt.Sprint(memInfo.ullTotalPhys / (1024 * 1024))
}

type intfInfo struct {
	Name       string
	MacAddress string
	Ipv4       []string
	Ipv6       []string
}

//网卡信息
func GetIntfs() []intfInfo {
	intf, err := net.Interfaces()
	if err != nil {
		return []intfInfo{}
	}
	var is = make([]intfInfo, len(intf))
	for i, v := range intf {
		ips, err := v.Addrs()
		if err != nil {
			continue
		}
		is[i].Name = v.Name
		is[i].MacAddress = v.HardwareAddr.String()
		for _, ip := range ips {
			if strings.Contains(ip.String(), ":") {
				is[i].Ipv6 = append(is[i].Ipv6, ip.String())
			} else {
				is[i].Ipv4 = append(is[i].Ipv4, ip.String())
			}
		}
	}
	return is
}

//主板信息
func GetMotherboardInfo() string {
	var s = []struct {
		Product string
	}{}
	err := wmi.Query("SELECT  Product  FROM Win32_BaseBoard WHERE (Product IS NOT NULL)", &s)
	if err != nil {
		return ""
	}
	return s[0].Product
}

//BIOS信息
func GetBiosInfo() string {
	var s = []struct {
		Name string
	}{}
	err := wmi.Query("SELECT Name FROM Win32_BIOS WHERE (Name IS NOT NULL)", &s) // WHERE (BIOSVersion IS NOT NULL)
	if err != nil {
		return ""
	}
	return s[0].Name
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
	return origData[:(length - unpadding)]
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

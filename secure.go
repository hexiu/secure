//开发一个个人使用的密码加密系统，内容存在与七牛云存储


package main

import "fmt"
import (
	"crypto/des"
	"os"
	"log"
	//"crypto/cipher"
	"bytes"
	"crypto/cipher"
)

// 加密使用的key ， 为8位字符
const des_key  = "hjhailmw"

func main()  {
	EnCoding()
	DeCoding()
}
//对指定文件的数据进行加密
func EnCoding()  {
	Cipher,err:=des.NewCipher([]byte(des_key))
	checkError(err)
	sFile,err:=os.OpenFile("src.txt",os.O_RDONLY,os.ModePerm)
	checkError(err)
	dFile,err:=os.OpenFile("des.secure",os.O_WRONLY|os.O_CREATE,os.ModePerm)
	checkError(err)
	stat,err:=sFile.Stat()
	size := stat.Size()
	var src []byte = make([]byte,size)
	_,err=sFile.Read(src)
	srci:=PKCS5Padding(src,Cipher.BlockSize())
	checkError(err)
	blockMode:=cipher.NewCBCEncrypter(Cipher,[]byte(des_key))
	crypted := make([]byte,len(srci))
	blockMode.CryptBlocks(crypted,srci)
	dFile.Write(crypted)
	defer sFile.Close()
	defer dFile.Close()
}

//对加密文件进行解密操作
func DeCoding()  {
	dFile,err:=os.OpenFile("des.secure",os.O_RDONLY,os.ModePerm)
	checkError(err)
	stat,err:=dFile.Stat()
	checkError(err)
	size := stat.Size()
	dst:=make([]byte,size)
	dFile.Read(dst)
	defer dFile.Close()
	Cipher,err := des.NewCipher([]byte(des_key))
	checkError(err)
	blockMode:=cipher.NewCBCDecrypter(Cipher,[]byte(des_key))
	src := make([]byte,len(dst))
	blockMode.CryptBlocks(src,dst)
	src=PKCS5UnPadding(src)
	fmt.Println(src,string(src))
}

//汇集数据
func PKCS5UnPadding(originData []byte) []byte  {
	length:=len(originData)
	unpadding:=int(originData[length-1])
	return originData[:length-unpadding]
}

//拆分数据
func PKCS5Padding(ciphertext []byte,blockSize int) []byte {
	padding := blockSize -len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)},padding)
	return append(ciphertext,padtext...)
}

func checkError(err error)  {
	if err!=nil{
		log.Println(err)
	}
}




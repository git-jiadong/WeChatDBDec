package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
)

const (
	keySize         = 32
	defaultIter     = 64000
	defaultPageSize = 4096
)

func DecryptDataBase(path string, password []byte, expPath string) error {
	sqliteFileHeader := []byte("SQLite format 3")
	sqliteFileHeader = append(sqliteFileHeader, byte(0))

	// Read the encrypted file
	blist, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	salt := blist[:16]
	key := pbkdf2HMAC(password, salt, defaultIter, keySize)

	page1 := blist[16:defaultPageSize]

	macSalt := xorBytes(salt, 0x3a)
	macKey := pbkdf2HMAC(key, macSalt, 2, keySize)

	hashMac := hmac.New(sha1.New, macKey)
	hashMac.Write(page1[:len(page1)-32])
	hashMac.Write([]byte{1, 0, 0, 0})

	if !hmac.Equal(hashMac.Sum(nil), page1[len(page1)-32:len(page1)-12]) {
		return fmt.Errorf("incorrect password")
	}

	pages := make([][]byte, 0)
	for i := defaultPageSize; i < len(blist); i += defaultPageSize {
		pages = append(pages, blist[i:i+defaultPageSize])
	}
	pages = append([][]byte{page1}, pages...)

	outFilePath := expPath
	outFile, err := os.Create(outFilePath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Write SQLite file header
	_, err = outFile.Write(sqliteFileHeader)
	if err != nil {
		return err
	}

	for _, page := range pages {
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		iv := page[len(page)-48 : len(page)-32]
		stream := cipher.NewCBCDecrypter(block, iv)
		decrypted := make([]byte, len(page)-48)
		stream.CryptBlocks(decrypted, page[:len(page)-48])
		_, err = outFile.Write(decrypted)
		if err != nil {
			return err
		}
		_, err = outFile.Write(page[len(page)-48:])
		if err != nil {
			return err
		}
	}

	return nil
}

func pbkdf2HMAC(password, salt []byte, iter, keyLen int) []byte {
	dk := make([]byte, keyLen)
	loop := (keyLen + sha1.Size - 1) / sha1.Size
	key := make([]byte, 0, len(salt)+4)
	u := make([]byte, sha1.Size)
	for i := 1; i <= loop; i++ {
		key = key[:0]
		key = append(key, salt...)
		key = append(key, byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
		hmac := hmac.New(sha1.New, password)
		hmac.Write(key)
		digest := hmac.Sum(nil)
		copy(u, digest)
		for j := 2; j <= iter; j++ {
			hmac.Reset()
			hmac.Write(digest)
			digest = hmac.Sum(digest[:0])
			for k, di := range digest {
				u[k] ^= di
			}
		}
		copy(dk[(i-1)*sha1.Size:], u)
	}
	return dk
}

func xorBytes(a []byte, b byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b
	}
	return result
}

func main() {

	str := os.Args[1]
	// 将十六进制字符串解码为字节
	password, err := hex.DecodeString(str)
	if err != nil {
		fmt.Println("解码出错:", err)
		return
	}

	fmt.Println(hex.EncodeToString(password))

	inputFile := os.Args[2]
	outputFile := inputFile + ".dec.db"
	err = DecryptDataBase(inputFile, password, outputFile)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Decryption successful!")
	}
}

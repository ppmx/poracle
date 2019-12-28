package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
)

// this is the top secret crypto key for this backend. It is only
// shared with some imaginary frontend or even some other function
// in this backend...
var crypto_key = []byte("3452851383948128")

func handler(w http.ResponseWriter, r *http.Request) {
	// A valid query looks like: '/search?data=base64(ciphertext)'

	query := r.URL.Query().Get("data")
	if len(query) == 0 {
		fmt.Fprintf(w, "[!] missing data")
		return
	}

	// 0. step: create decoding cipher suite
	block, err := aes.NewCipher(crypto_key)
	if err != nil {
		fmt.Fprintf(w, "[!] internal error")
		return
	}

	// 1. step: decode given data
	data, err := base64.URLEncoding.DecodeString(query)
	if err != nil {
		fmt.Fprintf(w, "[!] decoding (base64) error")
		return
	}

	// 2. step: extract initialization vector and the ciphertext
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext) % aes.BlockSize != 0 {
		fmt.Fprintf(w, "[!] ciphertext length mismatch")
		return
	}

	// 3. step: decrypt ciphertext
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// 4. step: check PKCS#7 padding and unpad if possible
	data, err = pkcs7_unpad(ciphertext, aes.BlockSize)
	if err != nil {
		fmt.Fprintf(w, "[!] error %s", err)
		return
	}

	// Let's simulate some backend operation...
	fmt.Fprintf(w, "[+] no results found :(")
}

func pkcs7_unpad(data []byte, blocksize int) ([]byte, error) {
	if len(data) % blocksize != 0 {
		return nil, errors.New("invalid PKCS#7 padding")
	}

	value := data[len(data) - 1]
	count := int(value)

	if count == 0 || count > len(data) {
		return nil, errors.New("invalid PKCS#7 padding")
	}

	for off := 0; off < count; off++ {
		if data[len(data) - count + off] != value {
			return nil, errors.New("invalid PKCS#7 padding")
		}
	}

	return data[:len(data) - count], nil
}

func main() {
	http.HandleFunc("/search", handler)
	http.ListenAndServe("127.0.0.1:8080", nil)
}


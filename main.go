package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"syscall/js"

	"github.com/minio/argon2"
	"github.com/secure-io/sio-go"
	"github.com/secure-io/sio-go/sioutil"
	"golang.org/x/crypto/pbkdf2"
)

const (
	argon2idAESGCM           = 0x00
	argon2idChaCHa20Poly1305 = 0x01
	pbkdf2AESGCM             = 0x02
)

const (
	argon2idTime    = 1
	argon2idMemory  = 64 * 1024
	argon2idThreads = 4
	pbkdf2Cost      = 8192
)

func EncryptData(password string, data []byte) ([]byte, error) {
	salt := sioutil.MustRandom(32)
	var (
		id     byte
		err    error
		stream *sio.Stream
	)

	key := argon2.IDKey([]byte(password), salt, argon2idTime, argon2idMemory, argon2idThreads, 32)

	if sioutil.NativeAES() {
		stream, err = sio.AES_256_GCM.Stream(key)
		if err != nil {
			return nil, err
		}
		id = argon2idAESGCM
	} else {
		stream, err = sio.ChaCha20Poly1305.Stream(key)
		if err != nil {
			return nil, err
		}
		id = argon2idChaCHa20Poly1305
	}

	nonce := sioutil.MustRandom(stream.NonceSize())
	// ciphertext = salt || AEAD ID | nonce | encrypted data
	cLen := int64(len(salt)+1+len(nonce)+len(data)) + stream.Overhead(int64(len(data)))
	ciphertext := bytes.NewBuffer(make([]byte, 0, cLen)) // pre-alloc correct length

	// Prefix the ciphertext with salt, AEAD ID and nonce
	ciphertext.Write(salt)
	ciphertext.WriteByte(id)
	ciphertext.Write(nonce)

	w := stream.EncryptWriter(ciphertext, nonce, nil)
	if _, err = w.Write(data); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return ciphertext.Bytes(), nil
}

func DecryptData(password string, data io.Reader) ([]byte, error) {
	var (
		salt  [32]byte
		id    [1]byte
		nonce [8]byte // This depends on the AEAD but both used ciphers have the same nonce length.
	)

	if _, err := io.ReadFull(data, salt[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(data, id[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(data, nonce[:]); err != nil {
		return nil, err
	}

	var (
		err    error
		stream *sio.Stream
	)
	switch {
	case id[0] == argon2idAESGCM:
		key := argon2.IDKey([]byte(password), salt[:], argon2idTime, argon2idMemory, argon2idThreads, 32)
		stream, err = sio.AES_256_GCM.Stream(key)
	case id[0] == argon2idChaCHa20Poly1305:
		key := argon2.IDKey([]byte(password), salt[:], argon2idTime, argon2idMemory, argon2idThreads, 32)
		stream, err = sio.ChaCha20Poly1305.Stream(key)
	case id[0] == pbkdf2AESGCM:
		key := pbkdf2.Key([]byte(password), salt[:], pbkdf2Cost, 32, sha256.New)
		stream, err = sio.AES_256_GCM.Stream(key)
	default:
		err = errors.New("madmin: invalid encryption algorithm ID")
	}
	if err != nil {
		return nil, err
	}

	plaintext, err := ioutil.ReadAll(stream.DecryptReader(data, nonce[:], nil))
	if err != nil {
		return nil, err
	}
	return plaintext, err
}

func encrypt(_this js.Value, args []js.Value) interface{} {
	_data := []byte(args[1].String())
	_text, err := EncryptData(args[0].String(), _data)
	if err != nil {
		return js.ValueOf(nil)
	}
	return js.ValueOf(base64.StdEncoding.EncodeToString(_text))
}

func decrypt(this js.Value, args []js.Value) interface{} {
	_data, err := base64.StdEncoding.DecodeString(args[1].String())
	_text, err := DecryptData(args[0].String(), bytes.NewReader(_data))
	if err != nil {
		return js.ValueOf(nil)
	}
	return js.ValueOf(string(_text))
}

func main() {
	js.Global().Set("mcw_encrypt", js.FuncOf(encrypt))
	js.Global().Set("mcw_decrypt", js.FuncOf(decrypt))
	select {}
}

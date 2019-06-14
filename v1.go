package gocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

/*
 * Version 1 uses AES-256-GCM encryption
 *
 * Encypted payload is defined as
 * | version(16) | nonce(12) | authTag(16) | encryptedData(n) |
 *
 */

// standard GCM sizes
const (
	Version1             = 1
	gcmStandardNonceSize = 12
	gcmTagSize           = 16
)

// encryptV1 performs a v1 encryption and returns an encrypted payload
func encryptV1(key, data []byte) ([]byte, error) {
	keyHash := hashKey(key)

	// create a new AES cipher
	block, err := aes.NewCipher(keyHash)
	if err != nil {
		return nil, err
	}

	// generate a nonce
	nonce := make([]byte, gcmStandardNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// create a GCM cipher
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// generate the ciphertext
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)

	// get the encrypted data by stripping the authTag
	encryptedDataBytes := ciphertext[:len(ciphertext)-gcmTagSize]

	// get the auth tag from the end
	authTag := ciphertext[len(ciphertext)-gcmTagSize:]

	// concat the encryption data
	encryptedData := append(nonce, authTag...)
	encryptedData = append(encryptedData, encryptedDataBytes...)

	// make and return payload
	return MakePayload(Version1, encryptedData)
}

// decryptV1 decrypts version 1 encrypted data
func decryptV1(key, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < (VersionLength + gcmStandardNonceSize + gcmTagSize + 1) {
		return nil, fmt.Errorf("encrypted data is not a valid length")
	}
	keyHash := hashKey(key)

	// create a new AES cipher
	block, err := aes.NewCipher(keyHash)
	if err != nil {
		return nil, err
	}

	// get the details from the encrypted data payload
	nonce := encryptedData[:gcmStandardNonceSize]
	tag := encryptedData[gcmStandardNonceSize : gcmStandardNonceSize+gcmTagSize]
	data := encryptedData[gcmStandardNonceSize+gcmTagSize:]

	// add the tag to the end of the data
	ciphertext := append(data, tag...)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// decrypt and return the data
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

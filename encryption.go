package gocrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// VersionLength length of byte array containing verison data
const VersionLength = 16

// MinimumVersion minimum supported encryption version
const MinimumVersion = 1

// MaximumVersion maximum supported encryption version
const MaximumVersion = 1

// ErrUnsupportedVersion unsupported encryption version
var ErrUnsupportedVersion = errors.New("unsupported encryption version")

// VersionBytes converts a version to a byte array with range validation
func VersionBytes(version uint16) ([]byte, error) {
	if version < MinimumVersion || version > MaximumVersion {
		return nil, ErrUnsupportedVersion
	}
	buf := make([]byte, VersionLength)
	binary.LittleEndian.PutUint16(buf, version)
	return buf, nil
}

// SplitPayload returns the version and encrypted data as separate variables
// by splitting the payload
func SplitPayload(payload []byte) (uint16, []byte, error) {
	if len(payload) < VersionLength+1 {
		return 0, nil, fmt.Errorf("payload is an invalid length")
	}

	version := binary.LittleEndian.Uint16(payload[:VersionLength])
	data := payload[VersionLength:]

	if version < MinimumVersion || version > MaximumVersion {
		return 0, nil, ErrUnsupportedVersion
	}

	return version, data, nil
}

// MakePayload creates a payload containing the version and encrypted data
func MakePayload(version uint16, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < 1 {
		return nil, fmt.Errorf("no encrypted data provided")
	}

	// convert the version to a byte array
	versionBytes, err := VersionBytes(version)
	if err != nil {
		return nil, err
	}

	// append the payload bytes to the version bytes
	payload := append(versionBytes, encryptedData...)
	return payload, nil
}

// NewSecretKey generates a new secret key of specified length
func NewSecretKey(length int) ([]byte, error) {
	if length%128 > 0 {
		return nil, fmt.Errorf("key length must be a multiple of 128")
	}

	key := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	return key, nil
}

// NewSecretKeyBase64 generates a new secret key of specified length
func NewSecretKeyBase64(length int) (string, error) {
	key, err := NewSecretKey(length)
	if err != nil {
		return "", err
	}
	b64key := base64.StdEncoding.EncodeToString(key)
	return b64key, nil
}

// hashes the key
func hashKey(key []byte) []byte {
	hash := sha256.New()
	hash.Write(key)
	return hash.Sum(nil)
}

// Decrypt decrypts a payload and returns its bytes
func Decrypt(key, payload []byte) ([]byte, error) {
	version, encryptedData, err := SplitPayload(payload)
	if err != nil {
		return nil, err
	}

	switch version {
	case 1:
		return decryptV1(key, encryptedData)
	default:
		return nil, ErrUnsupportedVersion
	}
}

// Encrypt encrypts data with optional version
func Encrypt(key, data []byte, version ...*uint16) ([]byte, error) {
	v := uint16(MaximumVersion)
	if len(version) > 0 {
		v = *version[0]
	}

	switch v {
	case 1:
		return encryptV1(key, data)
	default:
		return nil, ErrUnsupportedVersion
	}
}

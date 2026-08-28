package tooling

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	secret := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedSecret := base64.RawStdEncoding.EncodeToString(secret)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", 0x13, argon2Memory, argon2Time, argon2Threads, encodedSalt, encodedSecret), nil
}

func VerifyPassword(hash, password string) bool {
	salt, secret, err := decodeArgon2Hash(hash)
	if err != nil {
		return false
	}
	computed := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return constantTimeEqual(computed, secret)
}

func decodeArgon2Hash(hash string) (salt, secret []byte, err error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return nil, nil, fmt.Errorf("invalid hash format")
	}

	var memory, time, threads uint32
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, err
	}

	secret, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, err
	}

	return salt, secret, nil
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

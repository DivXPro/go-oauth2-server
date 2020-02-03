package password

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"golang.org/x/crypto/bcrypt"
)

// VerifyPassword compares password and the hashed password
func VerifyPassword(passwordHash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
}

// HashPassword creates a Bcrypt password hash
func HashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), 3)
}

func VerifyPassword2(passwordHash, password string, userID string, secret string, salt string) bool {
	return passwordHash == HashPassword2(password, userID, secret, salt)
}

func HashPassword2(password string, userID string, secret string, salt string) string {
	hmacSha1 := hmac.New(sha1.New, []byte(secret))
	hmacSha1.Write([]byte(password + "_" + userID + "_" + salt))
	passSha1 := hex.EncodeToString(hmacSha1.Sum(nil))
	return "V2====" + base64.StdEncoding.EncodeToString([]byte(passSha1))
}

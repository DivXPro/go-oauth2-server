package password

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"golang.org/x/crypto/bcrypt"
	"log"
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
	hashPassword := HashPassword2(password, userID, secret, salt)
	log.Println(hashPassword)
	return passwordHash == hashPassword
}

func HashPassword2(password string, userID string, secret string, salt string) string {
	hmacSha1 := hmac.New(sha1.New, []byte(secret))
	str := password + "_" + userID + "_" + salt
	hmacSha1.Write([]byte(str))
	hexStr := hex.EncodeToString(hmacSha1.Sum(nil))
	return "V2====" + base64.StdEncoding.EncodeToString([]byte(hexStr))
}

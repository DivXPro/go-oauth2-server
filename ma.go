package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	// Sign a sample payload. Calling the signer returns a protected JWS object,
	// which can then be serialized for output afterwards. An error would
	// indicate a problem in an underlying cryptographic primitive.
	var claims = jwt.Claims{
		Issuer: "123",
	}
	jwt, err := MakeRSASignedJWT(claims, privateKey)

	fmt.Printf(jwt)
}

func MakeRSASignedJWT(claims interface{}, key *rsa.PrivateKey) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	raw, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}
	return raw, nil
}

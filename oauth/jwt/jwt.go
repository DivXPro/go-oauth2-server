package jwt

import (
	"crypto/rsa"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

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

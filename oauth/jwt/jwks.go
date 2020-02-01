package jwt

import (
	"encoding/json"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
)

func GetJWKsFromFile(fileName string) *jose.JSONWebKeySet {
	if fileName == "" {
		fileName = "jwks.json"
	}
	if data, err := ioutil.ReadFile(fileName); err == nil {
		var jwks = &jose.JSONWebKeySet{}
		if err := json.Unmarshal(data, &jwks); err != nil {
			return nil
		}
		return jwks
	}
	return nil
}

func GetJWKFromFile(fileName string) *jose.JSONWebKey {
	if fileName == "" {
		fileName = "jwks.json"
	}
	if data, err := ioutil.ReadFile(fileName); err == nil {
		var jwk = &jose.JSONWebKey{}
		if err := json.Unmarshal(data, &jwk); err != nil {
			return nil
		}
		return jwk
	}
	return nil
}

func MakeJWKs(jwks []jose.JSONWebKey) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: jwks}
}

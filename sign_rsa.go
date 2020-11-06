package signgo

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
)

const (
	BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"
	END_RSA_PRIVATE_KEY   = "-----END RSA PRIVATE KEY-----"
	BEGIN_PUBLIC_KEY      = "-----BEGIN PUBLIC KEY-----"
	END_PUBLIC_KEY        = "-----END PUBLIC KEY-----"
)

//验签
//signContent：需要签名的内容字符串
//publicKey：公钥
//sign：私钥的签名结果
//hs：签名算法
func VerifyRsaSign(signContent, publicKey, sign string, hs crypto.Hash) (bool, error) {
	pk, err := ParsePublicKey(publicKey)
	if err != nil {
		return false, err
	}

	hashed := hs.New()
	hashed.Write([]byte(signContent))

	btSign, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(pk, hs, hashed.Sum(nil), btSign)
	if err != nil {
		return false, err
	}
	return true, nil
}

//签名
//signContent：签名内容
//privateKey：私钥
//hs：签名算法
func RsaSign(signContent, privateKey string, hs crypto.Hash) (string, error) {
	hashed := hs.New()
	hashed.Write([]byte(signContent))

	priKey, err := ParsePrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, priKey, hs, hashed.Sum(nil))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func ParsePublicKey(publicKey string) (*rsa.PublicKey, error) {
	publicKey = FormatPublicKey(publicKey)
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("publicKey error")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pubKey.(*rsa.PublicKey), nil
}

func FormatPublicKey(publicKey string) string {
	if !strings.HasPrefix(publicKey, BEGIN_PUBLIC_KEY) {
		publicKey = BEGIN_PUBLIC_KEY + "\n" + publicKey
	}
	if !strings.HasSuffix(publicKey, END_PUBLIC_KEY) {
		publicKey = publicKey + "\n" + END_PUBLIC_KEY
	}
	return publicKey
}

func ParsePrivateKey(privateKey string) (*rsa.PrivateKey, error) {
	privateKey = FormatPrivateKey(privateKey)
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New("publicKey error")
	}
	priKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return priKey.(*rsa.PrivateKey), nil
}

func FormatPrivateKey(privateKey string) string {
	if !strings.HasPrefix(privateKey, BEGIN_RSA_PRIVATE_KEY) {
		privateKey = BEGIN_RSA_PRIVATE_KEY + "\n" + privateKey
	}
	if !strings.HasSuffix(privateKey, END_RSA_PRIVATE_KEY) {
		privateKey = privateKey + "\n" + END_RSA_PRIVATE_KEY
	}
	return privateKey
}

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

var (
	begin_rsa_private_key = "-----BEGIN RSA PRIVATE KEY-----"
	end_rsa_private_key   = "-----END RSA PRIVATE KEY-----"
	begin_public_key      = "-----BEGIN PUBLIC KEY-----"
	end_public_key        = "-----END PUBLIC KEY-----"
)

//RSA验签
//signContent：签名内容
//publicKey：公钥
//sign：RsaSign()的签名结果
//hs：签名算法
func VerifyRsaSign(signContent []byte, publicKey, sign string, hs crypto.Hash) (bool, error) {
	pk, err := ParsePublicKey(publicKey)
	if err != nil {
		return false, err
	}

	hashed := hs.New()
	hashed.Write(signContent)

	deBt, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(pk, hs, hashed.Sum(nil), deBt)
	if err != nil {
		return false, err
	}
	return true, nil
}

//RSA签名，返回base64编码后的签名结果
//signContent：签名内容
//privateKey：私钥
//hs：签名算法
func RsaSign(signContent []byte, privateKey string, hs crypto.Hash) (string, error) {
	hashed := hs.New()
	hashed.Write(signContent)

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
	if !strings.HasPrefix(publicKey, begin_public_key) {
		publicKey = begin_public_key + "\n" + publicKey
	}
	if !strings.HasSuffix(publicKey, end_public_key) {
		publicKey = publicKey + "\n" + end_public_key
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
	if !strings.HasPrefix(privateKey, begin_rsa_private_key) {
		privateKey = begin_rsa_private_key + "\n" + privateKey
	}
	if !strings.HasSuffix(privateKey, end_rsa_private_key) {
		privateKey = privateKey + "\n" + end_rsa_private_key
	}
	return privateKey
}

//RSA加密，返回 base64 编码的密文
func RsaEncrypt(msg []byte, publicKey string) (string, error) {
	key, err := ParsePublicKey(publicKey)
	if err != nil {
		return "", err
	}

	bt, err := rsa.EncryptPKCS1v15(rand.Reader, key, msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bt), nil
}

//RSA解密
func RsaDecrypt(encodeString, privateKey string) ([]byte, error) {
	key, err := ParsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	bt, err := base64.StdEncoding.DecodeString(encodeString)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, key, bt)
}

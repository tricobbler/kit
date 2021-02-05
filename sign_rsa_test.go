package signgo

import (
	"crypto"
	"testing"
)

var (
	signContent = `{"name":"mayb","age":99,"car":[{"brand":"BMW"}]}`

	//私钥
	privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJD7Ga41L0i9bzNnMMtAspGapEyx5F5YCAbcEFGJgXtitizodPDl9yXTsSn1HPVPO58ew4rnvl2yVsIv8D/D04CQbGvBbt/4LD1Xagsa3K+0ZNAqKkp9E5obH4aNDGFydzH8fUo/VLb/LmJME6i5K09g/w95vxF05zCGPLFDOsE1AgMBAAECgYBUSOaBFIJMs3R2WcNQJmippVFnFPRCtMLV2hHSlTIlXRmzueBiPA8Wep9AWTNgmZN7yhK8KkXNiuRNODlfmKTX9RXlPUcvCjEKrTDEGdiFy1XjK3tQNVjR1j6rDhstfrV8KaxNBMt8kgiQYbohU6hy7Xv+foeuNkhRix9vgzIrAQJBAMPsE5dLuQD67+oBSy71wnKUeDVkASSVfmtoWX5NJkbB9+n7J3Dj/42QMUGgJ0rOsccXlpnn0lla9ww4udOxw/ECQQC9cB9Ftbw6reWPoHuw51UVHsC2S+tTpd07OpEx3BltiSE+ctM3oc+fYZhrfGGY3mKzlCC6mh/BmfyNEIAPEEWFAkB7eM4n7UrceUi1erc9ExjGSRcw3qNxwNz5J7wuwsQ6l4d76BJFLQsi1hqUty/MD1Mum4kH2XdRZOiIxT8nUMKhAkEArKz5NHe1vd8pM0RbuyMCoR/JFeIZ/cNg5045bzNrUjb/QIc2FK3ALU2uu7tC0y9S1NIfCzjV3YlZddQmhpSUaQJAKAUq3zO7atFy25Scso2aFvtZO9Ywr59+VApOTDPzE7ziAlK0YgoJXUFt4q+PVJeqSi5/4Pr2JY2trbO9/Ddo0A=="

	//公钥
	publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCQ+xmuNS9IvW8zZzDLQLKRmqRMseReWAgG3BBRiYF7YrYs6HTw5fcl07Ep9Rz1TzufHsOK575dslbCL/A/w9OAkGxrwW7f+Cw9V2oLGtyvtGTQKipKfROaGx+GjQxhcncx/H1KP1S2/y5iTBOouStPYP8Peb8RdOcwhjyxQzrBNQIDAQAB"
)

func TestRsaSign(t *testing.T) {
	type args struct {
		signContent []byte
		privateKey  string
		hs          crypto.Hash
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "RSA签名",
			args: args{
				signContent: []byte(signContent),
				privateKey:  privateKey,
				hs:          crypto.SHA256,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RsaSign(tt.args.signContent, tt.args.privateKey, tt.args.hs)
			if (err != nil) != tt.wantErr {
				t.Errorf("RsaSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestVerifyRsaSign(t *testing.T) {
	sign, _ := RsaSign([]byte(signContent), privateKey, crypto.SHA256)
	type args struct {
		signContent []byte
		sign        []byte
		publicKey   string
		hs          crypto.Hash
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "RSA验签",
			args: args{
				signContent: []byte(signContent),
				sign:        sign,
				publicKey:   publicKey,
				hs:          crypto.SHA256,
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyRsaSign(tt.args.signContent, tt.args.sign, tt.args.publicKey, tt.args.hs)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyRsaSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyRsaSign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRsaEncrypt(t *testing.T) {
	type args struct {
		msg       []byte
		publicKey string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "RSA加密",
			args: args{
				msg:       []byte(signContent),
				publicKey: publicKey,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RsaEncrypt(tt.args.msg, tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("RsaEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRsaDecrypt(t *testing.T) {
	ciphertext, _ := RsaEncrypt([]byte(signContent), publicKey)

	type args struct {
		ciphertext []byte
		privateKey string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "RSA解密",
			args: args{
				ciphertext: ciphertext,
				privateKey: privateKey,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RsaDecrypt(tt.args.ciphertext, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("RsaDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRsaEncryptToBase64(t *testing.T) {
	type args struct {
		msg       []byte
		publicKey string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "RSA加密并转换为base64",
			args: args{
				msg:       []byte(signContent),
				publicKey: publicKey,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RsaEncryptToBase64(tt.args.msg, tt.args.publicKey); got == tt.want {
				t.Errorf("RsaEncryptToBase64() = %v, not want %v", got, tt.want)
			} else {
				t.Log(got)
			}
		})
	}
}

func TestRsaDecryptFromBase64(t *testing.T) {
	type args struct {
		str        string
		privateKey string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "RSA解密 RsaEncryptToBase64（RSA加密并转换为base64） 后的结果",
			args: args{
				str:        "jcUROokpkW2HlXGBiJU2E7QI6KNJxX4tejqFIlr2rXh6W6xapW8cSIPaggYLI97uRqxMnjM2Lk9nFDjRI6UmjkyxycKR28AHFPCqdyyfhHu/Unxr07BPhb1hQTYzl0gNM0fm33X1OpVANixtr8p3oQpm8QlhOjZ/Ua1VPTS9D0I=",
				privateKey: privateKey,
			},
			want: signContent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RsaDecryptFromBase64(tt.args.str, tt.args.privateKey); got != tt.want {
				t.Errorf("RsaDecryptFromBase64() = %v, want %v", got, tt.want)
			}
		})
	}
}

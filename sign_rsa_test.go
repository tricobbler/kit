package signgo

import (
	"crypto"
	"testing"
)

func TestRsaSign(t *testing.T) {
	signContent := `{"name":"mayb","age":99,"car":[{"brand":"BMW"}]}`

	//私钥 签名
	privateKey := "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJD7Ga41L0i9bzNnMMtAspGapEyx5F5YCAbcEFGJgXtitizodPDl9yXTsSn1HPVPO58ew4rnvl2yVsIv8D/D04CQbGvBbt/4LD1Xagsa3K+0ZNAqKkp9E5obH4aNDGFydzH8fUo/VLb/LmJME6i5K09g/w95vxF05zCGPLFDOsE1AgMBAAECgYBUSOaBFIJMs3R2WcNQJmippVFnFPRCtMLV2hHSlTIlXRmzueBiPA8Wep9AWTNgmZN7yhK8KkXNiuRNODlfmKTX9RXlPUcvCjEKrTDEGdiFy1XjK3tQNVjR1j6rDhstfrV8KaxNBMt8kgiQYbohU6hy7Xv+foeuNkhRix9vgzIrAQJBAMPsE5dLuQD67+oBSy71wnKUeDVkASSVfmtoWX5NJkbB9+n7J3Dj/42QMUGgJ0rOsccXlpnn0lla9ww4udOxw/ECQQC9cB9Ftbw6reWPoHuw51UVHsC2S+tTpd07OpEx3BltiSE+ctM3oc+fYZhrfGGY3mKzlCC6mh/BmfyNEIAPEEWFAkB7eM4n7UrceUi1erc9ExjGSRcw3qNxwNz5J7wuwsQ6l4d76BJFLQsi1hqUty/MD1Mum4kH2XdRZOiIxT8nUMKhAkEArKz5NHe1vd8pM0RbuyMCoR/JFeIZ/cNg5045bzNrUjb/QIc2FK3ALU2uu7tC0y9S1NIfCzjV3YlZddQmhpSUaQJAKAUq3zO7atFy25Scso2aFvtZO9Ywr59+VApOTDPzE7ziAlK0YgoJXUFt4q+PVJeqSi5/4Pr2JY2trbO9/Ddo0A=="

	sign, err := RsaSign(signContent, privateKey, crypto.SHA256)
	if err != nil {
		t.Error(err)
	} else {
		println("sign", sign)
	}

	//公钥验签
	publicKey := "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCQ+xmuNS9IvW8zZzDLQLKRmqRMseReWAgG3BBRiYF7YrYs6HTw5fcl07Ep9Rz1TzufHsOK575dslbCL/A/w9OAkGxrwW7f+Cw9V2oLGtyvtGTQKipKfROaGx+GjQxhcncx/H1KP1S2/y5iTBOouStPYP8Peb8RdOcwhjyxQzrBNQIDAQAB"

	if b, err := VerifyRsaSign(signContent, publicKey, sign, crypto.SHA256); err != nil {
		t.Error(err)
	} else if b {
		println("签名验证成功")
	} else {
		t.Error("验证签名失败")
	}

}

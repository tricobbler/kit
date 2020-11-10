# golang RSA签名与验签，加密与解密的实现
公私钥生成：```sh gen_rsa_key.sh```

### 签名流程（签名算法使用crypto.SHA256）
* 将json参数转成[]byte字节数组
* 字节数组使用SHA256WithRSA算法获取签名结果，再将签名结果进行base64编码得到签名串sign
* 将签名串sign通过请求头sign提交

### 验签流程
* 获取请求结果body字符串
* 获取请求头sign签名串，并对sign进行base64解码
* 使用公钥对body字符串和sign签名串进行验签

demo参考sign_rsa_test.go中的示例

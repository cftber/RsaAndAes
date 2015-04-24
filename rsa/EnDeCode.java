/////////////
//测试代码
 
public static void main(String[] args)
{
    EnDeCodeTest();
}
 
//加解密,模拟网络
static void EnDeCodeTest()
{
    try
    {
        //AES对称密钥
        String mingKey = "1A2B3C4D5E6F010203040506A7B8C9D0";
         
        //待加密明文
        String mingData = "ABCD1234中文测试";
         
        //使用AES_KEY加密数据
        String miData = CodeHelper.EncodeMessage("", mingData, mingKey);
         
        //使用PublicKey加密AES对称密钥
        InputStream inStream = new FileInputStream("D:/rsa/public_rsa.cer");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
        PublicKey pubKey = cert.getPublicKey();
         
        //加密后的AES对称密钥
        String miKey = CodeHelper.EncodeKey("", mingKey, pubKey);
         
        //通过网络交互数据 miData miKey
        String miKey_ = miKey;
        String miData_ = miData;
         
        //使用PrivateKey解密AES对称密钥
        // 密钥仓库
        KeyStore ks = KeyStore.getInstance("PKCS12");
 
        // 读取密钥仓库
        FileInputStream ksfis = new FileInputStream("D:/rsa/private_rsa.pfx");
        BufferedInputStream ksbufin = new BufferedInputStream(ksfis);
 
        char[] keyPwd = "password".toCharArray();
        ks.load(ksbufin, keyPwd);
        // 从密钥仓库得到私钥
        PrivateKey priK = (PrivateKey) ks.getKey("test", keyPwd);
         
        //明文AES密钥
        String mingKey_ = CodeHelper.DecodeKey("", miKey_, priK);
         
        //解密数据
        String mingData_ = CodeHelper.DecodeMessage("", miData_, mingKey_);
         
        System.out.print("Result:" + mingData_ + "\r\n");
    }
    catch(Exception e)
    {
        System.out.print(e);
    }
}
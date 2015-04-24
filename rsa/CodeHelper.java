
/**   
 * @author GaoFeng 
 * @email	 kaster@163.com
 */     

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

@SuppressWarnings("restriction")
public class CodeHelper
{
	private static byte toByte(char c) 
	{
	    byte b = (byte) "0123456789ABCDEF".indexOf(c);
	    return b;
	}
	
	public static byte[] hexStringToByte(String hex) 
	{
	    int len = (hex.length() / 2);
	    byte[] result = new byte[len];
	    char[] achar = hex.toCharArray();
	    for (int i = 0; i < len; i++) 
	    {
	    	int pos = i * 2;
	    	result[i] = (byte) (toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
	    }
	    return result;
	}

	public static final String bytesToHexString(byte[] bArray) 
	{
		StringBuffer sb = new StringBuffer(bArray.length);
	    String sTemp;
	    for (int i = 0; i < bArray.length; i++) 
	    {
	    	sTemp = Integer.toHexString(0xFF & bArray[i]);
	    	if (sTemp.length() < 2)
	    	{
	    		sb.append(0);
	    	}
	     sb.append(sTemp.toUpperCase());
	    }
	    return sb.toString();
	}
	
	/////////////////////////////
	//Base64解码
	public static byte[] Base64De(String base64_msg) throws IOException
	{
		BASE64Decoder base64De = null;
		try
		{
			BASE64Decoder base64Decoder = new BASE64Decoder();
			base64De = base64Decoder;
			return base64De.decodeBuffer(base64_msg.replace(" ", ""));
		}
		finally
		{
			base64De = null;
		}
	}
	
	//Base64编码
	public static String Base64En(byte[] byteMsg) throws IOException
	{
		BASE64Encoder base64En = null;
		try
		{
			base64En = new BASE64Encoder();
			return base64En.encode(byteMsg).replace("\r\n", "");
		}
		finally
		{
			base64En = null;
		}
	}
	
	//DES密文解密
	public static byte[] DesDecrypt(byte[] byteMi, String strKey) 
				throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		return CodeHelper.Des(byteMi, strKey, Cipher.DECRYPT_MODE);
	}
	
	//DES密文解密
	public static byte[] DesEncrypt(byte[] byteMi, String strKey) 
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException 
	{
		
		return CodeHelper.Des(byteMi, strKey, Cipher.ENCRYPT_MODE);
	}
	
	//DES加解密
	private static byte[] Des(byte[] byteData, String strKey, int opmode) 
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = null;
		try
		{
			DESKeySpec desKeySpec = new DESKeySpec(CodeHelper.hexStringToByte(strKey));
    	    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
    		Key key = keyFactory.generateSecret(desKeySpec);
    		
    		cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    		cipher.init(opmode, key);
    		
    		return cipher.doFinal(byteData);
		}
		finally
		{
			cipher = null;
		}	
	}
	
	//AES密文解密
	public static byte[] AesDecrypt(byte[] byteMi, String strKey) 
				throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		return CodeHelper.Aes(byteMi, strKey, Cipher.DECRYPT_MODE);
	}
	
	//AES密文加密
	public static byte[] AesEncrypt(byte[] byteMi, String strKey) 
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException 
	{
		
		return CodeHelper.Aes(byteMi, strKey, Cipher.ENCRYPT_MODE);
	}
	
	//AES加解密
	private static byte[] Aes(byte[] byteData, String strKey, int opmode) 
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = null;
		try
		{
			SecretKeySpec aesKey = new SecretKeySpec(CodeHelper.hexStringToByte(strKey), "AES");
    		cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    		cipher.init(opmode, aesKey);
    		
    		return cipher.doFinal(byteData);
		}
		finally
		{
			cipher = null;
		}	
	}
	
	//RSA密文解密
	public static byte[] RsaDecrypt(byte[] byteMi, Key pKey) 
				throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		return CodeHelper.Rsa(byteMi, pKey, Cipher.DECRYPT_MODE);
	}
	
	//RSA密文加密
	public static byte[] RsaEncrypt(byte[] byteMi, Key pKey) 
				throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		return CodeHelper.Rsa(byteMi, pKey, Cipher.ENCRYPT_MODE);
	}
	
	//RSA加解密
	//Key对象为PrivateKey或PublicKey
	private static byte[] Rsa(byte[] byteData, Key pKey, int opmode) 
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = null;
		try
		{
    		cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    		cipher.init(opmode, pKey);
    		
    		return cipher.doFinal(byteData);
		}
		finally
		{
			cipher = null;
		}	
	}
	/////////////////////////////////
	
	//加密数据
	public static String EncodeMessage(String msgID, String oriData, String strKey) throws Exception
	{
		String strMi = "";
		
		byte[] byteMing = null;
		byte[] byteMi = null;

		try
		{	
			//原始数据
			System.out.print("EncodeMessage:" + msgID + " ORI:" + oriData + "\r\n");
			byteMing = oriData.getBytes("UTF8");
			
			//ZIP压缩
			//byteMing = Zip.jzlib(byteMing);	
			//System.out.print("EncodeMessage:" + msgID + " Zip:" + CodeHelper.bytesToHexString(byteMing));
			
			//AES加密
			byteMi = CodeHelper.AesEncrypt(byteMing, strKey);
			System.out.print("EncodeMessage:" + msgID + " AesEncrypt:" + CodeHelper.bytesToHexString(byteMi) + "\r\n");
			
			//BASE64编码，最终密文
			strMi = CodeHelper.Base64En(byteMi);
			System.out.print("EncodeMessage:" + msgID + " Base64En:" + strMi + "\r\n");	
		}
		finally
		{
			byteMing = null;
			byteMi = null;
		}
		return strMi;
	}
	
	//解密数据
	public static String DecodeMessage(String msgID, String oriData, String strKey) throws Exception
	{
		String strMing = "";
		
		byte[] byteMing = null;
		byte[] byteMi = null;

		try
		{	
			//原始数据
			System.out.print("DecodeMessage:" + msgID + " ORI:" + oriData + "\r\n");
			
			//BASE64解码
			byteMi = CodeHelper.Base64De(oriData);		
			System.out.print("DecodeMessage:" + msgID + " Base64De:" + CodeHelper.bytesToHexString(byteMi) + "\r\n");
			
			//AES解密
			byteMing = CodeHelper.AesDecrypt(byteMi, strKey);
			System.out.print("DecodeMessage:" + msgID + " AesDecrypt:" + CodeHelper.bytesToHexString(byteMing) + "\r\n");
			
			//ZIP解压缩
			//byteMing = Zip.unjzlib(byteMing);
			
			strMing = new String(byteMing, "UTF8");
			
			//最终解密数据
			System.out.print("DecodeMessage:" + msgID + " UnZip:" + strMing + "\r\n");	
		}
		finally
		{
			byteMing = null;
			byteMi = null;
		}
		return strMing;
	}
	

	//RSA解密KEY
	public static String DecodeKey(String msgID, String oriData, PrivateKey pKey) throws Exception
	{
		String strMing = "";
		
		byte[] byteMing = null;
		byte[] byteMi = null;

		try
		{	
			//原始数据
			System.out.print("DecodeKey:" + msgID + " ORI:" + oriData + "\r\n");
			
			//BASE64解码
			byteMi = CodeHelper.Base64De(oriData);		
			System.out.print("DecodeKey:" + msgID + " Base64De:" + CodeHelper.bytesToHexString(byteMi) + "\r\n");
			
			//RSA解密
			byteMing = CodeHelper.RsaDecrypt(byteMi, pKey);
			strMing = new String(byteMing, "UTF8");
			
			//最终解密数据
			System.out.print("DecodeKey:" + msgID + " RsaDecrypt:" + strMing + "\r\n");	
		}
		finally
		{
			byteMing = null;
			byteMi = null;
		}
		return strMing;
	}
	
	//RSA加密KEY
	public static String EncodeKey(String msgID, String oriData, PublicKey pKey) throws Exception
	{
		String strMi = "";
		
		byte[] byteMing = null;
		byte[] byteMi = null;

		try
		{	
			//原始数据
			System.out.print("EncodeKey:" + msgID + " ORI:" + oriData + "\r\n");
			
			byteMing = oriData.getBytes("UTF8");
			
			//RSA加密
			byteMi = CodeHelper.RsaEncrypt(byteMing, pKey);
			System.out.print("EncodeKey:" + msgID + " RsaEncrypt:" + CodeHelper.bytesToHexString(byteMi) + "\r\n");	
			
			//BASE64编码,最终密文
			strMi = CodeHelper.Base64En(byteMi);
			System.out.print("EncodeKey:" + msgID + " Base64En:" + strMi + "\r\n");	
		}
		finally
		{
			byteMing = null;
			byteMi = null;
		}
		return strMi;
	}
	
	
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
}

package rgw_java;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Date;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.util.DateUtil;
import org.apache.commons.lang.StringUtils;

import sun.misc.BASE64Encoder;

public class rgw_java_admin {
    static String accessKey = "accessKey";
    static String secretKey = "secretKey";
    static String endPoint = "http://127.0.0.1";

	
	public static void main(String[] args) {
		//getMetatadata();
		getReplicaLog();
	};
	
	public static void getReplicaLog()
	{
		HttpURLConnection conn = null;  
        BufferedInputStream in = null;  
        BufferedOutputStream out = null;  
        try { 
        	URL url = new URL(endPoint + "/admin/replica_log");
            conn = (HttpURLConnection) url.openConnection();  
            conn.setRequestMethod("GET");  
            conn.setDoOutput(true);  
  
            String contentType = "application/xml";  
            Date date = new Date();  
            String dateString = DateUtil.formatDate(date, DateUtil.PATTERN_RFC1036);  
            String sign = sign("GET", "", contentType, dateString, "/admin/replica_log", null);  
            conn.setRequestProperty("Date", dateString);  
            conn.setRequestProperty("Authorization", sign);  
            conn.setRequestProperty("Content-Type", contentType);  
            
            System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());
			
            String objectName = "getReplicaLog.txt";
            in = new BufferedInputStream(conn.getInputStream());  
            
            File localFile = new File("d:/gdownload/" + objectName);  
            if (!localFile.getParentFile().exists()) {  
                localFile.getParentFile().mkdirs();  
            }  
            out = new BufferedOutputStream(new FileOutputStream(localFile, false));  
  
            byte[] buffer = new byte[1024];  
            int p = 0;  
            while ((p = in.read(buffer)) != -1) {  
                out.write(buffer, 0, p);  
                out.flush();  
            }  
        } catch (Exception e) {  
            e.printStackTrace();  
            throw new RuntimeException(e);  
        } finally {  
            close(in);  
            close(out);  
        }    
	}
	
	// 返回 region的配置信息
	public static void getConfig()
	{
		HttpURLConnection conn = null;  
        BufferedInputStream in = null;  
        BufferedOutputStream out = null;  
        try { 
        	URL url = new URL(endPoint + "/admin/config");
            conn = (HttpURLConnection) url.openConnection();  
            conn.setRequestMethod("GET");  
            conn.setDoOutput(true);  
  
            String contentType = "application/xml";  
            Date date = new Date();  
            String dateString = DateUtil.formatDate(date, DateUtil.PATTERN_RFC1036);  
            String sign = sign("GET", "", contentType, dateString, "/admin/config", null);  
            conn.setRequestProperty("Date", dateString);  
            conn.setRequestProperty("Authorization", sign);  
            conn.setRequestProperty("Content-Type", contentType);  
            
            System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());
			
            String objectName = "getConfig.txt";
            in = new BufferedInputStream(conn.getInputStream());  
            
            File localFile = new File("d:/gdownload/" + objectName);  
            if (!localFile.getParentFile().exists()) {  
                localFile.getParentFile().mkdirs();  
            }  
            out = new BufferedOutputStream(new FileOutputStream(localFile, false));  
  
            byte[] buffer = new byte[1024];  
            int p = 0;  
            while ((p = in.read(buffer)) != -1) {  
                out.write(buffer, 0, p);  
                out.flush();  
            }  
        } catch (Exception e) {  
            e.printStackTrace();  
            throw new RuntimeException(e);  
        } finally {  
            close(in);  
            close(out);  
        }    
	}
	
	public static void getMetatadata()
	{
		HttpURLConnection conn = null;  
        BufferedInputStream in = null;  
        BufferedOutputStream out = null;  
        try { 
        	URL url = new URL(endPoint + "/admin/metadata/bucket");
            conn = (HttpURLConnection) url.openConnection();  
            conn.setRequestMethod("GET");  
            conn.setDoOutput(true);  
  
            String contentType = "application/xml";  
            Date date = new Date();  
            String dateString = DateUtil.formatDate(date, DateUtil.PATTERN_RFC1036);  
            String sign = sign("GET", "", contentType, dateString, "/admin/metadata/bucket", null);  
            conn.setRequestProperty("Date", dateString);  
            conn.setRequestProperty("Authorization", sign);  
            conn.setRequestProperty("Content-Type", contentType);  
            
            System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());
			
            String objectName = "getMetatadata.txt";
            in = new BufferedInputStream(conn.getInputStream());  
            
            File localFile = new File("d:/gdownload/" + objectName);  
            if (!localFile.getParentFile().exists()) {  
                localFile.getParentFile().mkdirs();  
            }  
            out = new BufferedOutputStream(new FileOutputStream(localFile, false));  
  
            byte[] buffer = new byte[1024];  
            int p = 0;  
            while ((p = in.read(buffer)) != -1) {  
                out.write(buffer, 0, p);  
                out.flush();  
            }  
        } catch (Exception e) {  
            e.printStackTrace();  
            throw new RuntimeException(e);  
        } finally {  
            close(in);  
            close(out);  
        }    
	}
	
	public static void getLog()
	{
		HttpURLConnection conn = null;  
        BufferedInputStream in = null;  
        BufferedOutputStream out = null;  
        try { 
        	URL url = new URL(endPoint + "/admin/log");
            conn = (HttpURLConnection) url.openConnection();  
            conn.setRequestMethod("GET");  
            conn.setDoOutput(true);  
  
            String contentType = "application/xml";  
            Date date = new Date();  
            String dateString = DateUtil.formatDate(date, DateUtil.PATTERN_RFC1036);  
            String sign = sign("GET", "", contentType, dateString, "/admin/log", null);  
            conn.setRequestProperty("Date", dateString);  
            conn.setRequestProperty("Authorization", sign);  
            conn.setRequestProperty("Content-Type", contentType);  
            
            System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());
			
            String objectName = "getLog.txt";
            in = new BufferedInputStream(conn.getInputStream());  
            
            File localFile = new File("d:/gdownload/" + objectName);  
            if (!localFile.getParentFile().exists()) {  
                localFile.getParentFile().mkdirs();  
            }  
            out = new BufferedOutputStream(new FileOutputStream(localFile, false));  
  
            byte[] buffer = new byte[1024];  
            int p = 0;  
            while ((p = in.read(buffer)) != -1) {  
                out.write(buffer, 0, p);  
                out.flush();  
            }  
        } catch (Exception e) {  
            e.printStackTrace();  
            throw new RuntimeException(e);  
        } finally {  
            close(in);  
            close(out);  
        }    
	}
	
	public static void getopstate()
	{
		HttpURLConnection conn = null;  
        BufferedInputStream in = null;  
        BufferedOutputStream out = null;  
        try { 
        	URL url = new URL(endPoint + "/admin/opstate");
            conn = (HttpURLConnection) url.openConnection();  
            conn.setRequestMethod("GET");  
            conn.setDoOutput(true);  
  
            String contentType = "application/xml";  
            Date date = new Date();  
            String dateString = DateUtil.formatDate(date, DateUtil.PATTERN_RFC1036);  
            String sign = sign("GET", "", contentType, dateString, "/admin/opstate", null);  
            conn.setRequestProperty("Date", dateString);  
            conn.setRequestProperty("Authorization", sign);  
            conn.setRequestProperty("Content-Type", contentType);  
            
            System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());
			
            String objectName = "getopstate.txt";
            in = new BufferedInputStream(conn.getInputStream());  
            
            File localFile = new File("d:/gdownload/" + objectName);  
            if (!localFile.getParentFile().exists()) {  
                localFile.getParentFile().mkdirs();  
            }  
            out = new BufferedOutputStream(new FileOutputStream(localFile, false));  
  
            byte[] buffer = new byte[1024];  
            int p = 0;  
            while ((p = in.read(buffer)) != -1) {  
                out.write(buffer, 0, p);  
                out.flush();  
            }  
        } catch (Exception e) {  
            e.printStackTrace();  
            throw new RuntimeException(e);  
        } finally {  
            close(in);  
            close(out);  
        }    
	}
	
	private static void close(Closeable c) {
		try {
			if (c != null) {
				c.close();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static String md5file(File file) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance("MD5");
		BufferedInputStream in = new BufferedInputStream(new FileInputStream(
				file));
		byte[] buf = new byte[1024 * 100];
		int p = 0;
		while ((p = in.read(buf)) != -1) {
			messageDigest.update(buf, 0, p);
		}
		in.close();
		byte[] digest = messageDigest.digest();

		BASE64Encoder encoder = new BASE64Encoder();
		return encoder.encode(digest);
	}

	public static String sign(String httpVerb, String contentMD5,
			String contentType, String date, String resource,
			Map<String, String> metas) {

		String stringToSign = httpVerb + "\n"
				+ StringUtils.trimToEmpty(contentMD5) + "\n"
				+ StringUtils.trimToEmpty(contentType) + "\n" + date + "\n";
		if (metas != null) {
			for (Map.Entry<String, String> entity : metas.entrySet()) {
				stringToSign += StringUtils.trimToEmpty(entity.getKey()) + ":"
						+ StringUtils.trimToEmpty(entity.getValue()) + "\n";
			}
		}
		stringToSign += resource;
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			byte[] keyBytes = secretKey.getBytes("UTF8");
			SecretKeySpec signingKey = new SecretKeySpec(keyBytes, "HmacSHA1");
			mac.init(signingKey);
			byte[] signBytes = mac.doFinal(stringToSign.getBytes("UTF8"));
			String signature = encodeBase64(signBytes);
			return "AWS" + " " + accessKey + ":" + signature;
		} catch (Exception e) {
			throw new RuntimeException("MAC CALC FAILED.");
		}

	}

	private static String encodeBase64(byte[] data) {
		String base64 = new String(Base64.encodeBase64(data));
		if (base64.endsWith("\r\n"))
			base64 = base64.substring(0, base64.length() - 2);
		if (base64.endsWith("\n"))
			base64 = base64.substring(0, base64.length() - 1);

		return base64;
	}
}

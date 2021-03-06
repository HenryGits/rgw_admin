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
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.util.DateUtil;
import org.apache.commons.lang.StringUtils;

import com.amazonaws.internal.StaticCredentialsProvider;

import sun.misc.BASE64Encoder;
import sun.print.resources.serviceui;

public class rgw_create_bucket {
	
    static String accessKey = "accessKey";
    static String secretKey = "secretKey";
    static String endPoint = "http://127.0.0.1";
	
	public static void getbucketlocation(String bucket) {
		HttpURLConnection conn = null;
	    BufferedInputStream in = null;
	    BufferedOutputStream out = null;
	    
	    try {
	    	URL url = new URL(endPoint + "/"+ bucket +"?location");
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();            
			String dateString = DateUtil.formatDate(date,DateUtil.PATTERN_RFC1036);
			
			String sign = sign("GET", "", contentType, dateString,"/"+ bucket +"?location", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "getbucketlocation.txt";
			in = new BufferedInputStream(conn.getInputStream());
			File localFile = new File("d:/gdownload/" + objectName);
			if (!localFile.getParentFile().exists()) {
				localFile.getParentFile().mkdirs();
			}
			out = new BufferedOutputStream(new FileOutputStream(localFile,
					false));

			byte[] buffer = new byte[1024];
			int p = 0;
			while ((p = in.read(buffer)) != -1) {
				out.write(buffer, 0, p);
				out.flush();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}finally{
			close(in);
			close(out);
		}
	}
	public static void createBucket(String bucket) {
	     
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		
		String localtionxml = "<CreateBucketConfiguration><LocationConstraint>default:new-placement</LocationConstraint></CreateBucketConfiguration>";
		try {
			URL url = new URL(endPoint + "/"+ bucket);
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("PUT");
			conn.setDoOutput(true);
			
			byte[] keyBytes = localtionxml.getBytes("UTF8");
			String contentMD5 = encodeBase64(keyBytes);
			System.out.println("ContentMD5: " + contentMD5);

			String contentType = "application/xml";
			Date date = new Date();
			Map<String,String> meta = new HashMap<String,String>();
            meta.put("x-amz-acl", "public-read");
            
			String dateString = DateUtil.formatDate(date,DateUtil.PATTERN_RFC1036);
			String sign = sign("PUT", contentMD5, contentType, dateString,"/"+bucket, meta);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);
			conn.setRequestProperty("x-amz-acl", "public-read");			
			conn.setRequestProperty("Content-MD5", contentMD5);

			out = new BufferedOutputStream(conn.getOutputStream());
			byte[] bufferout = localtionxml.getBytes("UTF-8");
			out.write(bufferout);
			out.flush();

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "createBucket.txt";
			in = new BufferedInputStream(conn.getInputStream());
			File localFile = new File("d:/gdownload/" + objectName);
			if (!localFile.getParentFile().exists()) {
				localFile.getParentFile().mkdirs();
			}
			out = new BufferedOutputStream(new FileOutputStream(localFile,
					false));

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
	
	/** SET BUCKET ACL **/
	public static void setBucketAcl(String bucket)
	{
		HttpURLConnection conn = null;  
        BufferedInputStream in = null;  
        BufferedOutputStream out = null;  
       
        String acl_xml = "<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>xxxtest</ID></Owner><AccessControlList>"
        		+ "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>xxxtest</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>"
        		+ "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>testxxxx</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>"
        		+ "</AccessControlList></AccessControlPolicy>";
       	
        try {  
            URL url = new URL(endPoint +"/"+ bucket +"/?acl");  
            conn = (HttpURLConnection) url.openConnection();  
            conn.setRequestMethod("PUT");  
            conn.setDoOutput(true); 
            
            byte[] keyBytes = acl_xml.getBytes("UTF8");            
            String contentMD5 = encodeBase64(keyBytes);
            
            System.out.println("ContentMD5: " + contentMD5);
  
            String contentType = "application/xml";            
            Date date = new Date();  
            String dateString = DateUtil.formatDate(date, DateUtil.PATTERN_RFC1036);  
            String sign = sign("PUT", contentMD5, contentType, dateString, "/"+ bucket +"/?acl",null);  
            conn.setRequestProperty("Date", dateString);  
            conn.setRequestProperty("Authorization", sign);  
            conn.setRequestProperty("Content-Type", contentType); 
            conn.setRequestProperty("Content-MD5", contentMD5); 
            
            out = new BufferedOutputStream(conn.getOutputStream());
            
            byte[] buffer = acl_xml.getBytes("UTF-8");  
            out.write(buffer);  
            out.flush();  
            
            System.out.println("sign : " + sign);
            int status = conn.getResponseCode(); 
            System.out.println("http status: " + status);
            System.out.println("after:\n" + conn.getHeaderFields());
            
        } catch (Exception e) {  
            e.printStackTrace();  
            throw new RuntimeException(e);  
        } finally {  
            close(in);  
            close(out);  
        }  
	}
	
	public static void unlinkBucket(String userId,String bucket) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/bucket?bucket="+ bucket+ "&uid="+userId);
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("POST");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("POST", "", contentType, dateString,
					"/admin/bucket", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "unlinkBucket.txt";
			in = new BufferedInputStream(conn.getInputStream());
			File localFile = new File("d:/gdownload/" + objectName);
			if (!localFile.getParentFile().exists()) {
				localFile.getParentFile().mkdirs();
			}
			out = new BufferedOutputStream(new FileOutputStream(localFile,
					false));

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
	
	/** LINK BUCKET **/
	public static void linkBucket(String userId,String bucket) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/bucket?bucket="+ bucket+ "&uid="+userId);
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("PUT");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("PUT", "", contentType, dateString,
					"/admin/bucket", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "linkBucket.txt";
			in = new BufferedInputStream(conn.getInputStream());
			File localFile = new File("d:/gdownload/" + objectName);
			if (!localFile.getParentFile().exists()) {
				localFile.getParentFile().mkdirs();
			}
			out = new BufferedOutputStream(new FileOutputStream(localFile,
					false));

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
	
	/** GET BUCKET ACL **/
	public static void getBucketAcl(String bucket)
	{
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/"+ bucket +"?acl");
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("GET", "", contentType, dateString,
					"/"+ bucket +"?acl", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "getBucketAcl.txt";
			in = new BufferedInputStream(conn.getInputStream());
			File localFile = new File("d:/gdownload/" + objectName);
			if (!localFile.getParentFile().exists()) {
				localFile.getParentFile().mkdirs();
			}
			out = new BufferedOutputStream(new FileOutputStream(localFile,
					false));

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
	public static void main(String[] args) {
		//String bucket = "biubiu";
		String bucket = "piapia";
		// admin create bucket
		//createBucket(bucket);
		getbucketlocation(bucket);
		//setBucketAcl(bucket);
		// unlink （admin）
		//unlinkBucket("xxxtest", bucket);
		// link (testxxxx)
		//linkBucket("testxxxx", bucket);
		//getBucketAcl(bucket);
		//setBucketAcl(bucket);
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

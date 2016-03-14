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
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.util.DateUtil;
import org.apache.commons.lang.StringUtils;

import com.sun.jmx.snmp.Timestamp;

import sun.misc.BASE64Encoder;

public class rgw_java_rest_object {
	static String accessKey = "accessKey";
    static String secretKey = "secretKey";
    static String endPoint = "http://127.0.0.1";
	
	public static void main(String[] args) {		
		//headObject(bucket,object);
		getObject(bucket,object);
	}
	public static void headObject(String bucket,String object)  {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			Date dateSince = new Date();
			Calendar cal = Calendar.getInstance();
			cal.setTime(dateSince);
			cal.add(Calendar.MINUTE, -1);
			
			String tsString = DateUtil.formatDate(cal.getTime(),
					DateUtil.PATTERN_RFC1036);
			URL url = new URL(endPoint + "/" + bucket + "/" + object);
			
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("HEAD");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("HEAD", "", contentType, dateString,
					"/" + bucket + "/" + object, null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);
			//conn.setRequestProperty("If-Modified-Since",tsString);
			//conn.setRequestProperty("If-Match","your-tag");

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());
            if("200".equals(conn.getResponseCode()) || "304".equals(conn.getResponseCode()))
            {
            	String objectName = "headObject.txt";
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
            	
            }
			

		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} finally {
			close(in);
			close(out);
		}
		
	}
	public static File getObject(String bucket, String objectName) {  
		  
        HttpURLConnection conn = null;  
        BufferedInputStream in = null;  
        BufferedOutputStream out = null;  
        try {  
            URL url = new URL(endPoint + "/" +bucket +"/" + objectName);  
            conn = (HttpURLConnection) url.openConnection();  
            conn.setRequestMethod("GET");  
            conn.setDoOutput(true);  
  
            String contentType = "application/xml";  
            Date date = new Date();  
            String dateString = DateUtil.formatDate(date, DateUtil.PATTERN_RFC1036);  
            String sign = sign("GET", "", contentType, dateString, "/" + bucket + "/" + objectName, null);  
            conn.setRequestProperty("Date", dateString);  
            conn.setRequestProperty("Authorization", sign);  
            conn.setRequestProperty("Content-Type", contentType);  
            conn.setRequestProperty("Range", "bytes=0-121596");  
//            if (start != null && end != null) {  
//                conn.setRequestProperty("Range", "bytes=" + start + "-" + end);  
//            }  
//  
//            if (StringUtils.isNotBlank(etag)) {  
//                conn.setRequestProperty("If-None-Match", etag);  
//            }  
  
            int status = conn.getResponseCode(); 
            System.out.println("http status: " + status);
            if (status == 304) {  
                return null;  
            }  
  
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
            System.out.println("after:\n" + conn.getHeaderFields());
            return localFile;  
        } catch (Exception e) {  
            e.printStackTrace();  
            throw new RuntimeException(e);  
        } finally {  
            close(in);  
            close(out);  
        }  
  
    }  
	
	
	public static void deleteBucket(String bucket) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/" + bucket +"?purge-objects=True");
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("DELETE");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("DELETE", "", contentType, dateString,
					"/" + bucket, null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "deleteBucket.txt";
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
	
	public static void getBuckets() {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/");
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("GET", "", contentType, dateString,
					"/", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "getBucket.txt";
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
	
	public static void headBucket(String bucket)  {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			Date dateSince = new Date();
			Calendar cal = Calendar.getInstance();
			cal.setTime(dateSince);
			cal.add(Calendar.MINUTE, -1);
			
			String tsString = DateUtil.formatDate(cal.getTime(),
					DateUtil.PATTERN_RFC1036);
			URL url = new URL(endPoint + "/" + bucket);
			
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("HEAD");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("HEAD", "", contentType, dateString, "/" + bucket, null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());
            if("200".equals(conn.getResponseCode()) || "304".equals(conn.getResponseCode()))
            {
            	String objectName = "headObject.txt";
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
            	
            }
			

		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} finally {
			close(in);
			close(out);
		}
		
	}
	
	public static void removeObjFromBuck(String bucket, String object) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/bucket?bucket="
		       + bucket
		       + "&object="
		       + object);
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("DELETE");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("DELETE", "", contentType, dateString,
					"/admin/bucket", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "removeObjFromBuck.txt";
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
	
	public static void  listBucket(String bucket) {
    	HttpURLConnection conn = null;  
        BufferedInputStream in = null;  
        BufferedOutputStream out = null;  
        try {  
            URL url = new URL(endPoint + "/"+bucket+"?delimiter=/");
            conn = (HttpURLConnection) url.openConnection();  
            conn.setRequestMethod("GET");  
            conn.setDoOutput(true);  
  
            String contentType = "application/xml";  
            Date date = new Date();  
            String dateString = DateUtil.formatDate(date, DateUtil.PATTERN_RFC1036);  
            String sign = sign("GET", "", contentType, dateString, "/"+bucket, null);  
            conn.setRequestProperty("Date", dateString);  
            conn.setRequestProperty("Authorization", sign);  
            conn.setRequestProperty("Content-Type", contentType);  
            
            int status = conn.getResponseCode(); 
            System.out.println("http status : " + status);
            System.out.println("http after  : \n" + conn.getHeaderFields());
            
            if(200 != status)
            	return;
            
            String objectName = "listBucket.txt";
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

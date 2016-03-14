package rest.log;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
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

public class rgw_rest_metatdata {
	static String accessKey = "accessKey";
	static String secretKey = "sercretKey";
	static String endPoint = "http://10.10.3.62";

	public static void main(String[] args) {
		get_meta_sections(); // ["bucket","bucket.instance","user"]
		String type_buck = "bucket";
		String type_inst = "bucket.instance";
		String type_user = "user";
		list_metadata_keys(type_buck); // ["testbuck","testnew_buck"]
		list_metadata_keys(type_inst); // ["testbuck:master.4182.1","testnew_buck:master.4186.1"]
		list_metadata_keys(type_user); // ["testnewuser","master","testuser","slave"]
		//get_metadata_with_keys(type_buck, "testbuck");
		//get_metadata_with_keys(type_inst, "testbuck:master.4182.1");
		//get_metadata_with_keys(type_user, "testuser");
	
		getConfig();
	}
	

	public static void get_metadata_with_keys(String type, String key) {
				HttpURLConnection conn = null;  
		        BufferedInputStream in = null;  
		        BufferedOutputStream out = null;  
		        try { 
		          
		        	URL url = new URL(endPoint+"/admin/metadata/" + type + "?key="+ key);         	
		            
		            conn = (HttpURLConnection) url.openConnection();  
		            conn.setRequestMethod("GET");  
		            conn.setDoOutput(true);  
		  
		            String contentType = "application/xml";  
		            Date date = new Date();  
		            String dateString = DateUtil.formatDate(date, DateUtil.PATTERN_RFC1036);  
		            String sign = sign("GET", "", contentType, dateString, "/admin/metadata/" +  type, null);  
		            conn.setRequestProperty("Date", dateString);  
		            conn.setRequestProperty("Authorization", sign);  
		            conn.setRequestProperty("Content-Type", contentType);  
		            
		            //System.out.println("http status : " + conn.getResponseCode());
					//System.out.println("http headers:\n" + conn.getHeaderFields());
					
					//System.out.println("---- body start ----");
					BufferedReader reader = new BufferedReader(new InputStreamReader(
							conn.getInputStream()));
					String readLine;
					while ((readLine = reader.readLine()) != null) {
						System.out.println(readLine);
					}
					reader.close();
					//System.out.println("---- body end ----");
		           
		        } catch (Exception e) {  
		            e.printStackTrace();  
		            throw new RuntimeException(e);  
		        } finally {  
		            close(in);  
		            close(out);  
		        }  
			}

	public static void list_metadata_keys(String type) {
			HttpURLConnection conn = null;  
	        BufferedInputStream in = null;  
	        BufferedOutputStream out = null;  
	        try { 
	          
	        	URL url = new URL(endPoint+"/admin/metadata/" + type);         	
	            
	            conn = (HttpURLConnection) url.openConnection();  
	            conn.setRequestMethod("GET");  
	            conn.setDoOutput(true);  
	  
	            String contentType = "application/xml";  
	            Date date = new Date();  
	            String dateString = DateUtil.formatDate(date, DateUtil.PATTERN_RFC1036);  
	            String sign = sign("GET", "", contentType, dateString, "/admin/metadata/" +  type, null);  
	            conn.setRequestProperty("Date", dateString);  
	            conn.setRequestProperty("Authorization", sign);  
	            conn.setRequestProperty("Content-Type", contentType);  
	            
	            //System.out.println("http status : " + conn.getResponseCode());
				//System.out.println("http headers:\n" + conn.getHeaderFields());
				
				//System.out.println("---- body start ----");
				BufferedReader reader = new BufferedReader(new InputStreamReader(
						conn.getInputStream()));
				String readLine;
				while ((readLine = reader.readLine()) != null) {
					System.out.println(readLine);
				}
				reader.close();
				//System.out.println("---- body end ----");
	           
	        } catch (Exception e) {  
	            e.printStackTrace();  
	            throw new RuntimeException(e);  
	        } finally {  
	            close(in);  
	            close(out);  
	        }  
		}
		
	// ["bucket","bucket.instance","user"]
	public static void get_meta_sections() {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {

			URL url = new URL(endPoint + "/admin/metadata");

			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("GET", "", contentType, dateString,
					"/admin/metadata", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			//System.out.println("http status : " + conn.getResponseCode());
			//System.out.println("http headers:\n" + conn.getHeaderFields());

			System.out.println("---- body start ----");
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					conn.getInputStream()));
			String readLine;
			while ((readLine = reader.readLine()) != null) {
				System.out.println(readLine);
			}
			reader.close();
			System.out.println("---- body end ----");

		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} finally {
			close(in);
			close(out);
		}
	}

	
	public static void getConfig() {
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
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("GET", "", contentType, dateString,
					"/admin/config", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			System.out.println("---- body start ----");
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					conn.getInputStream()));
			String readLine;
			while ((readLine = reader.readLine()) != null) {
				System.out.println(readLine);
			}
			reader.close();
			System.out.println("---- body end ----");
			
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

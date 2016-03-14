package rest.log;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
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

public class rgw_rest_replica_log {
	static String accessKey = "accessKey";
	static String secretKey = "sercretKey";
	static String endPoint = "http://10.10.3.62";

	public static void main(String[] args) {
		// 注意replica log仅会出现在备份zone上
		// rados -p .slave.log ls 
		// replica_log.testnew_buck replica_log.testbuck
		// data.replicalog.17 data.replicalog.128  rados -p .slave.log ls | grep replica | grep data | wc -l  = 128
		// meta.replicalog.24 meta.replicalog.24 meta.replicalog.53
		// metadata data  --> obj_log
		// bucket_index   --> bi_log
		
		String bi_type = "bucket-index";
	    String data_type = "data";
	    String metadata_type = "metadata";
	    
	  //{"marker":"1_1448343869.489474_10.1",
//	     "oldest_time":"0.000000",
//	     "markers":[{"entity":"radosgw-agent",
//	     "position_marker":"1_1448343869.489474_10.1",
//	     "position_time":"0.000000",
//	     "items_in_progress":[]}]}
	//
	//{"marker":"1_1448338061.424933_3.1",
//		"oldest_time":"0.000000",
//		"markers":[{"entity":"radosgw-agent",
//		"position_marker":"1_1448338061.424933_3.1",
//		"position_time":"0.000000",
//		"items_in_progress":[]}]}
	    
//	    for(int id = 1; id < 128; id++)
//	    {
//	    	getReplicaLogBounds(data_type, id);
//	    }
	    
	    // 对于metadata类型，只能获取存在的replica的id才是参数有效 比如上面

	    /*
	    getReplicaLogBounds(data_type, 13);
	    getReplicaLogBounds(data_type, 35);
	    getReplicaLogBounds(data_type, 49);
	    getReplicaLogBounds(data_type, 53);
	    getReplicaLogBounds(data_type, 42);
	    getReplicaLogBounds(data_type, 24);
	    */
	    

	  //{"marker":"00000000024.24.3",
	  //"oldest_time":"0.000000",
	  //"markers":[{"entity":"radosgw-agent","position_marker":"00000000024.24.3","position_time":"0.000000","items_in_progress":[]}]}
	  //{"marker":"00000000050.50.3",
	  //"oldest_time":"0.000000",
	  //"markers":[{"entity":"radosgw-agent","position_marker":"00000000050.50.3","position_time":"0.000000","items_in_progress":[]}]}
	    getReplicaLog_bilog_Bounds(bi_type,"testbuck:master.4182.1");
	    getReplicaLog_bilog_Bounds(bi_type,"testnew_buck:master.4186.1");
	}

	public static void getReplicaLogBounds(String type, int id) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/replica_log?type="+type +"&id=" + id);
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("GET", "", contentType, dateString,
					"/admin/replica_log", null);
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

	public static void getReplicaLog_bilog_Bounds(String type, String id) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/replica_log?type="+type +"&bucket-instance=" + id);
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("GET", "", contentType, dateString,
					"/admin/replica_log", null);
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

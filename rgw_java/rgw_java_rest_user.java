package rgw_java;

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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.util.DateUtil;
import org.apache.commons.lang.StringUtils;

import com.amazonaws.services.dynamodbv2.document.Item;

import sun.misc.BASE64Encoder;

public class rgw_java_rest_user {
	// admin ak sk
    static String accessKey = "accessKey";
    static String secretKey = "secretKey";
    static String endPoint = "http://127.0.0.1";

	public static void main(String[] args) {	
		// enable_user(userId);
		// enable_user(userId);
		// getUserInfo(userId);
		// createUser(userId);
		// deleteUser(userId);
		// modifyUser(userId);
		// getUserInfo(userId);
		// createSubUser(userId, subuserId);
		// getSubUserInfo(userId, subuserId);
		// modifySubUser(userId, subuserId);
		// deleteSubUser(userId, subuserId);
		// createKey(userId,subuserId);
		// removeKey(userId,subuserId,accessk);
		//listAllUsers();
	}

	public static void listAllUsers() {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/metadata/user");
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("GET", "", contentType, dateString,
					"/admin/metadata/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			if (200 != conn.getResponseCode())
				return;

			// System.out.println("---- body start ----");
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					conn.getInputStream()));
			String readLine;
			while ((readLine = reader.readLine()) != null) {
				System.out.println(readLine);
			}
			reader.close();

		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} finally {
			close(in);
			close(out);
		}
	}

	/** GET USER INFO **/
	public static void getUserInfo(String userId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/user?uid=" + userId);
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("GET", "", contentType, dateString,
					"/admin/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			//System.out.println("http status : " + conn.getResponseCode());
			//System.out.println("http headers:\n" + conn.getHeaderFields());

			if (200 != conn.getResponseCode())
				return;

			// System.out.println("---- body start ----");
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					conn.getInputStream()));
			String readLine;
			while ((readLine = reader.readLine()) != null) {
				System.out.println(readLine);
			}
			reader.close();
			

		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} finally {
			close(in);
			close(out);
		}
	}

	/** CREATE USER **/
	public static void createUser(String userId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/user?uid=" + userId
					+ "&display-name=abcxxxnew" + "&email=abc@xxx.com"
					+ "&key-type=s3" + "&access-key=XYZ1234567Z"
					+ "&secret-key=SECRETXYZQWERZXYU" + "&max-buckets=5"
					+ "&suspended=False"); // 不开启
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("PUT");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("PUT", "", contentType, dateString,
					"/admin/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "createUser.txt";
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

	public static void enable_user(String userId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/user?uid=" + userId
					+ "&suspended=False");
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("POST");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("POST", "", contentType, dateString,
					"/admin/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			BufferedReader reader = new BufferedReader(new InputStreamReader(
					conn.getInputStream()));
			String readLine;
			while ((readLine = reader.readLine()) != null) {
				System.out.println(readLine);
			}
			reader.close();

		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} finally {
			close(in);
			close(out);
		}
	}

	/** MODIFY USER **/
	public static void modifyUser(String userId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/user?uid=" + userId
					+ "&max-buckets=10" + "&email=abc@yyy.com");
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("POST");
			conn.setDoOutput(true);
			/** 或者按照 按照 json格式组织数据 **/
			// /String
			// postdata="{\"email\": \"mail@youweb.com\",\"max-buckets\": \"1024\"}";
			// /byte[] keyBytes = postdata.getBytes("UTF-8");
			// String contentMD5 = encodeBase64(keyBytes);
			// System.out.println("ContentMD5: " + contentMD5);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("POST", "", contentType, dateString,
					"/admin/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);
			// conn.setRequestProperty("Content-Length", ""+postdata.length());

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "modifyUser.txt";
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

	/** DELETE USER **/
	public static void deleteUser(String userId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/user?uid=" + userId
					+ "&purge-data=True"); // purge-data 清理用户的数据
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("DELETE");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("DELETE", "", contentType, dateString,
					"/admin/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			if (!"200".equals(conn.getResponseCode()))
				return;

			BufferedReader reader = new BufferedReader(new InputStreamReader(
					conn.getInputStream()));
			String readLine;
			while ((readLine = reader.readLine()) != null) {
				System.out.println(readLine);
			}
			reader.close();

		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} finally {
			close(in);
			close(out);
		}
	}

	/** GET SUBUSER INFO **/
	public static void getSubUserInfo(String userId, String subuserId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/user??subuser&uid=" + userId
					+ "&subuser=" + subuserId);
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("GET", "", contentType, dateString,
					"/admin/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "getSubUserInfo.txt";
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

	/** CREATE SUBUSER **/
	public static void createSubUser(String userId, String subuserId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/user?subuser&uid=" + userId
					+ "&subuser=" + subuserId + "&key-type=s3" + "&access=read");
			// + "&generate-secret=True"); //此选项会默认生成s3和swift两种key
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("PUT");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("PUT", "", contentType, dateString,
					"/admin/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "createSubUser.txt";
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

	/** MODIFY SUBUSER **/
	public static void modifySubUser(String userId, String subuserId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/user?subuser&uid=" + userId
					+ "&subuser=" + subuserId + "&key_type=s3" + "&access=read");
			// + "&generate-secret=True"); //此选项会默认生成s3和swift两种key
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("POST");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("POST", "", contentType, dateString,
					"/admin/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "modifySubUser.txt";
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

	/** DELETE SUBUSER **/
	public static void deleteSubUser(String userId, String subuserId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/user??subuser&uid=" + userId
					+ "&subuser=" + subuserId + "&purge-keys=True"); // 次选项不起作用
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("DELETE");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("DELETE", "", contentType, dateString,
					"/admin/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			if (200 != conn.getResponseCode())
				return;

			String objectName = "deleteSubUser.txt";
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

	/** CREATE USER/SUBUSER KEY **/
	public static void createKey(String userId, String subuserId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/user?key&uid=" + userId
					+ "&subuser=" + subuserId + "&key-type=s3"
					+ "&generate-key=True");

			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("PUT");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("PUT", "", contentType, dateString,
					"/admin/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "deleteSubUser.txt";
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

	/** REMOVE USER/SUBUSER KEY **/
	public static void removeKey(String userId, String subuserId, String accessk) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/user?key&uid=" + userId
					+ "&subuser=" + subuserId + "&access-key=" + accessk // keytype=s3是必须带上
					+ "&key-type=s3");
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("DELETE");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("DELETE", "", contentType, dateString,
					"/admin/user", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "deleteSubUser.txt";
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

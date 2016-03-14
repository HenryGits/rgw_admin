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
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.util.DateUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.http.client.utils.URLEncodedUtils;

import sun.misc.BASE64Encoder;

public class rgw_java_rest_usage {

	static String bucketName = "wodebuck";
    static String accessKey = "accessKey";
    static String secretKey = "secretKey";
    static String endPoint = "http://127.0.0.1";


	public static void main(String[] args) {
		// getUsagebyUid("testuserid");	
		// getUsage("testuserid");
	}

	public static void getUsagebyUid(String userId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {

			// String urlstr= endPoint + "/admin/bucket?stats=true&" + "uid="+
			// userId;
			URL url = new URL(endPoint + "/admin/bucket?uid=" + userId
					+ "&stats=true");

			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("GET", "", contentType, dateString,
					"/admin/bucket", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);
			in = new BufferedInputStream(conn.getInputStream());

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

	/** GET USAGE **/
	public static void getUsage(String userId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {

			Calendar calendar = Calendar.getInstance();
			calendar.setTime(new Date());

			calendar.add(Calendar.HOUR_OF_DAY, -24);
			String end = date2string(calendar.getTime(), "yyyy-MM-dd HH:mm:ss");
			calendar.add(Calendar.HOUR_OF_DAY, -1);
			String start = date2string(calendar.getTime(),
					"yyyy-MM-dd HH:mm:ss");
			System.out.println("end : " + end + " statrt: " + start);

			String urlstr = endPoint
					+ "/admin/usage?&show-summary=true&show-entries=false&"
					// + "uid="+ userId;
					+ "bucket=test1234" + "&start=" + start + "&end=" + end;

			urlstr = urlstr.replace(" ", "%20");
			System.out.println(urlstr);
			URL url = new URL(urlstr);

			// URL url = new
			// URL("http://192.168.182.139/admin/usage?uid=testuser&show-summary=true&show-entries=False");
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("GET", "", contentType, dateString,
					"/admin/usage", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "getUsage.txt";
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

	public static Date string2date(String dateStr, String conStr) {
		SimpleDateFormat dateFormat = new SimpleDateFormat(conStr);
		Date date = null;

		try {
			date = dateFormat.parse(dateStr);

		} catch (ParseException e) {
			e.printStackTrace();
		}

		return date;
	}

	public static String date2string(Date dateStr, String conStr) {
		SimpleDateFormat dateFormat = new SimpleDateFormat(conStr);
		String date = null;

		try {
			date = dateFormat.format(dateStr);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return date;
	}

	public static void trimUsage(String userId) {
		HttpURLConnection conn = null;
		BufferedInputStream in = null;
		BufferedOutputStream out = null;
		try {
			URL url = new URL(endPoint + "/admin/usage?uid=" + userId
					+ "&remove-all=False");
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("DELETE");
			conn.setDoOutput(true);

			String contentType = "application/xml";
			Date date = new Date();
			String dateString = DateUtil.formatDate(date,
					DateUtil.PATTERN_RFC1036);
			String sign = sign("DELETE", "", contentType, dateString,
					"/admin/usage", null);
			conn.setRequestProperty("Date", dateString);
			conn.setRequestProperty("Authorization", sign);
			conn.setRequestProperty("Content-Type", contentType);

			System.out.println("http status : " + conn.getResponseCode());
			System.out.println("http headers:\n" + conn.getHeaderFields());

			String objectName = "trimUsage.txt";
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

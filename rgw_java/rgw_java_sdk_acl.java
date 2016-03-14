package rgw_java;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.List;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.Protocol;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.S3ClientOptions;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.services.s3.model.HeadBucketRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.PutObjectResult;
import com.amazonaws.services.simpleworkflow.flow.core.TryCatchFinally;

public class rgw_java_sdk_acl {

	static String bucketName = "bucketName";
    static String accessKey = "accessKey";
    static String secretKey = "secretKey";
    static String endPoint = "http://127.0.0.1";
	 
	static AmazonS3 conn;
	static AWSCredentials credentials;
	
	
	public static void testConn() {
		credentials = new BasicAWSCredentials(accessKey, secretKey);

		ClientConfiguration clientConfig = new ClientConfiguration();
		clientConfig.setProtocol(Protocol.HTTP);

		conn = new AmazonS3Client(credentials, clientConfig);
		conn.setEndpoint(endPoint);

		S3ClientOptions s3ClientOptions = new S3ClientOptions();
		s3ClientOptions.setPathStyleAccess(true);
		conn.setS3ClientOptions(s3ClientOptions);

		System.out.println("conn succ!");
	}
	

	private static File createSampleFile() throws IOException {
		File file = File.createTempFile("aws-java-sdk-", ".txt");
		file.deleteOnExit();

		Writer writer = new OutputStreamWriter(new FileOutputStream(file));
		writer.write("12342234\n");		
		writer.close();

		return file;
	}
	
	public static void putObj(String key) {
		testConn();
		System.out.println("Uploading a new object to S3 from a file\n");
		try {
			PutObjectResult result = conn.putObject(new PutObjectRequest(bucketName, key, createSampleFile()));
			System.out.println("ETAG : " + result.getETag());
		} catch (AmazonServiceException ase) {
			System.out.println("Error Message:    " + ase.getMessage());
			System.out.println("HTTP Status Code: " + ase.getStatusCode());
			System.out.println("AWS Error Code:   " + ase.getErrorCode());
			System.out.println("Error Type:       " + ase.getErrorType());
			System.out.println("Request ID:       " + ase.getRequestId());
		} catch (AmazonClientException ace) {
			System.out.println("Error Message: " + ace.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void gen_url() {
		testConn();
		GeneratePresignedUrlRequest request = new GeneratePresignedUrlRequest(bucketName, "bbbb");
		System.out.println(conn.generatePresignedUrl(request));
	}
	
	public static void headObj(String key) {
		testConn();
		try {
			ObjectMetadata meta = conn.getObjectMetadata(bucketName, key);
			System.out.println(meta.getETag());
		} catch (Exception e) {
			// TODO: handle exception
		}
	}
	public static void main(String[] args) {
		//gen_url();
		headObj("time");
	}
	
    
}

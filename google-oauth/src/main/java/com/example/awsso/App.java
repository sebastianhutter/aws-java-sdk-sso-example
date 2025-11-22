package com.example.awsso;

import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.Key;

import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;

import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

/**
 * AWS SSO authentication using Google OAuth HTTP client library.
 *
 * This example demonstrates how to authenticate with AWS IAM Identity Center
 * using the OAuth 2.0 Device Authorization Grant flow (RFC 8628) implemented
 * with Google's HTTP client library instead of the AWS SDK.
 */
public class App {

    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();

    public static void main(String[] args) {
        if (args.length != 4) {
            System.err.println("Usage: App <startUrl> <region> <accountId> <roleName>");
            System.err.println(
                    "Example: App https://d-1234567890.awsapps.com/start eu-central-1 123456789012 AdministratorAccess");
            System.exit(1);
        }

        String startUrl = args[0];
        String region = args[1];
        String accountId = args[2];
        String roleName = args[3];

        try {
            // Step 1-4: Authenticate and get access token
            String accessToken = authenticate(startUrl, region);

            // Step 5: Get role credentials using the access token
            RoleCredentials credentials = getRoleCredentials(accessToken, region, accountId, roleName);

            // Step 6: Verify credentials by listing S3 buckets
            listS3Buckets(region, credentials);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Authenticates with AWS SSO using the Device Authorization Grant flow.
     */
    public static String authenticate(String startUrl, String region) throws IOException, InterruptedException {
        String oidcEndpoint = String.format("https://oidc.%s.amazonaws.com", region);

        // Step 1: Register the client
        System.out.println("Registering client...");
        RegisterClientResponse registerResponse = registerClient(oidcEndpoint);
        System.out.println("Client registered successfully");

        // Step 2: Start device authorization
        System.out.println("Starting device authorization...");
        DeviceAuthorizationResponse deviceAuth = startDeviceAuthorization(
                oidcEndpoint,
                registerResponse.clientId,
                registerResponse.clientSecret,
                startUrl);

        // Step 3: Display the user code and URL
        System.out.println("\n===========================================");
        System.out.println("Please visit: " + deviceAuth.verificationUriComplete);
        System.out.println("Verify access code: " + deviceAuth.userCode);
        System.out.println("===========================================\n");

        // Step 3.1: Open the verification URL in the default browser (optional)
        if (java.awt.Desktop.isDesktopSupported()) {
            try {
                java.awt.Desktop.getDesktop().browse(java.net.URI.create(deviceAuth.verificationUriComplete));
            } catch (Exception e) {
                System.out.println("Could not open browser automatically");
            }
        }

        // Step 4: Poll for token
        String accessToken = pollForToken(
                oidcEndpoint,
                registerResponse.clientId,
                registerResponse.clientSecret,
                deviceAuth.deviceCode,
                deviceAuth.interval != null ? deviceAuth.interval : 5);

        System.out.println("Authentication successful!\n");
        return accessToken;
    }

    /**
     * Registers a client with AWS SSO OIDC.
     */
    private static RegisterClientResponse registerClient(String oidcEndpoint) throws IOException {
        HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(
                request -> request.setParser(new JsonObjectParser(JSON_FACTORY)));

        Map<String, String> data = new HashMap<>();
        data.put("clientName", "my-java-app-google-oauth");
        data.put("clientType", "public");

        HttpRequest request = requestFactory.buildPostRequest(
                new GenericUrl(oidcEndpoint + "/client/register"),
                new JsonHttpContent(JSON_FACTORY, data));

        request.getHeaders().setContentType("application/json");

        HttpResponse response = request.execute();
        return response.parseAs(RegisterClientResponse.class);
    }

    /**
     * Starts the device authorization flow.
     */
    private static DeviceAuthorizationResponse startDeviceAuthorization(
            String oidcEndpoint,
            String clientId,
            String clientSecret,
            String startUrl) throws IOException {

        HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(
                request -> request.setParser(new JsonObjectParser(JSON_FACTORY)));

        Map<String, String> data = new HashMap<>();
        data.put("clientId", clientId);
        data.put("clientSecret", clientSecret);
        data.put("startUrl", startUrl);

        HttpRequest request = requestFactory.buildPostRequest(
                new GenericUrl(oidcEndpoint + "/device_authorization"),
                new JsonHttpContent(JSON_FACTORY, data));

        request.getHeaders().setContentType("application/json");

        HttpResponse response = request.execute();
        return response.parseAs(DeviceAuthorizationResponse.class);
    }

    /**
     * Polls for the access token after user authorization.
     */
    private static String pollForToken(
            String oidcEndpoint,
            String clientId,
            String clientSecret,
            String deviceCode,
            int interval) throws IOException, InterruptedException {

        HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(
                request -> request.setParser(new JsonObjectParser(JSON_FACTORY)));

        int pollInterval = interval * 1000;

        while (true) {
            Thread.sleep(pollInterval);

            Map<String, String> data = new HashMap<>();
            data.put("clientId", clientId);
            data.put("clientSecret", clientSecret);
            data.put("grantType", "urn:ietf:params:oauth:grant-type:device_code");
            data.put("deviceCode", deviceCode);

            HttpRequest request = requestFactory.buildPostRequest(
                    new GenericUrl(oidcEndpoint + "/token"),
                    new JsonHttpContent(JSON_FACTORY, data));

            request.getHeaders().setContentType("application/json");

            try {
                HttpResponse response = request.execute();
                TokenResponse tokenResponse = response.parseAs(TokenResponse.class);
                return tokenResponse.accessToken;
            } catch (HttpResponseException e) {
                // Parse error response from the exception content
                ErrorResponse errorResponse = JSON_FACTORY.createJsonParser(new StringReader(e.getContent()))
                        .parse(ErrorResponse.class);

                if ("authorization_pending".equals(errorResponse.error)) {
                    System.out.println("Waiting for authorization...");
                } else if ("slow_down".equals(errorResponse.error)) {
                    System.out.println("Slowing down polling...");
                    pollInterval += 5000;
                } else {
                    throw new IOException("Token request failed: " + errorResponse.error +
                            " - " + errorResponse.errorDescription, e);
                }
            }
        }
    }

    /**
     * Gets role credentials using the SSO access token.
     */
    public static RoleCredentials getRoleCredentials(
            String accessToken,
            String region,
            String accountId,
            String roleName) throws IOException {

        String ssoEndpoint = String.format("https://portal.sso.%s.amazonaws.com", region);

        HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(
                request -> request.setParser(new JsonObjectParser(JSON_FACTORY)));

        GenericUrl url = new GenericUrl(ssoEndpoint + "/federation/credentials");
        url.put("account_id", accountId);
        url.put("role_name", roleName);

        HttpRequest request = requestFactory.buildGetRequest(url);
        request.getHeaders().set("x-amz-sso_bearer_token", accessToken);

        HttpResponse response = request.execute();
        GetRoleCredentialsResponse credentialsResponse = response.parseAs(GetRoleCredentialsResponse.class);

        RoleCredentials credentials = credentialsResponse.roleCredentials;

        System.out.println("AWS Credentials:");
        System.out.println("Access Key: " + credentials.accessKeyId);
        System.out.println("Secret Key: " + credentials.secretAccessKey);
        System.out.println("Session Token: " + credentials.sessionToken);
        System.out.println("Expiration: " + credentials.expiration);

        return credentials;
    }

    /**
     * Lists S3 buckets to verify the credentials work.
     */
    public static void listS3Buckets(String region, RoleCredentials credentials) {
        Region awsRegion = Region.of(region);

        S3Client s3Client = S3Client.builder()
                .region(awsRegion)
                .credentialsProvider(() -> AwsSessionCredentials.create(
                        credentials.accessKeyId,
                        credentials.secretAccessKey,
                        credentials.sessionToken))
                .build();

        try {
            ListBucketsResponse listBucketsResponse = s3Client.listBuckets();
            System.out.println("\nS3 Buckets:");
            listBucketsResponse.buckets().forEach(bucket -> System.out.println("- " + bucket.name()));
        } catch (Exception e) {
            System.err.println("Failed to list S3 buckets: " + e.getMessage());
        } finally {
            s3Client.close();
        }
    }

    // ============== Response Model Classes ==============

    public static class RegisterClientResponse {
        @Key
        public String clientId;

        @Key
        public String clientSecret;

        @Key
        public Long clientIdIssuedAt;

        @Key
        public Long clientSecretExpiresAt;
    }

    public static class DeviceAuthorizationResponse {
        @Key
        public String deviceCode;

        @Key
        public String userCode;

        @Key
        public String verificationUri;

        @Key
        public String verificationUriComplete;

        @Key
        public Integer expiresIn;

        @Key
        public Integer interval;
    }

    public static class TokenResponse {
        @Key
        public String accessToken;

        @Key
        public String tokenType;

        @Key
        public Integer expiresIn;

        @Key
        public String refreshToken;

        @Key
        public String idToken;
    }

    public static class ErrorResponse {
        @Key
        public String error;

        @Key("error_description")
        public String errorDescription;
    }

    public static class GetRoleCredentialsResponse {
        @Key
        public RoleCredentials roleCredentials;
    }

    public static class RoleCredentials {
        @Key
        public String accessKeyId;

        @Key
        public String secretAccessKey;

        @Key
        public String sessionToken;

        @Key
        public Long expiration;
    }
}

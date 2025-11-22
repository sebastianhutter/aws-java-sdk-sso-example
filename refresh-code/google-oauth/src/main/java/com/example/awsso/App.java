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

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * AWS SSO authentication using Google OAuth HTTP client library.
 *
 * This example demonstrates the OAuth 2.0 Refresh Token Grant flow.
 * It first authenticates using Authorization Code flow to obtain tokens,
 * then demonstrates refreshing the access token using the refresh token.
 */
public class App {

    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
    private static final int CALLBACK_PORT = 65500;
    // callback url needs to use /oauth/callback!
    private static final String REDIRECT_URI = "http://127.0.0.1:" + CALLBACK_PORT + "/oauth/callback";

    /**
     * Holds the client registration info needed for token operations.
     */
    public static class ClientInfo {
        public final String clientId;
        public final String clientSecret;

        public ClientInfo(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }
    }

    public static void main(String[] args) {
        if (args.length != 5) {
            System.err.println("Usage: App <startUrl> <issuerUrl> <region> <accountId> <roleName>");
            System.err.println(
                    "Example: App https://d-1234567890.awsapps.com/start https://identitycenter.amazonaws.com/ssoins-1234567890123456 eu-central-1 123456789012 AdministratorAccess");
            System.exit(1);
        }

        String startUrl = args[0];
        String issuerUrl = args[1];
        String region = args[2];
        String accountId = args[3];
        String roleName = args[4];

        try {
            String oidcEndpoint = String.format("https://oidc.%s.amazonaws.com", region);

            // ============================================================
            // STEP 1: Initial authentication using Authorization Code flow
            // ============================================================
            System.out.println("=== STEP 1: Initial Authentication ===\n");

            // Register client (needed for both initial auth and refresh)
            System.out.println("Registering client...");
            System.out.println("Issuer URL: " + issuerUrl);
            RegisterClientResponse registerResponse = registerClient(oidcEndpoint, issuerUrl);
            System.out.println("Client registered successfully");
            System.out.println("Client ID: " + registerResponse.clientId + "\n");

            ClientInfo clientInfo = new ClientInfo(registerResponse.clientId, registerResponse.clientSecret);

            // Authenticate and get initial tokens
            TokenResponse initialTokens = authenticateWithAuthorizationCode(
                    oidcEndpoint, clientInfo, startUrl);

            System.out.println("Initial Access Token: " + initialTokens.accessToken.substring(0, 50) + "...");
            System.out.println("Refresh Token: " + initialTokens.refreshToken.substring(0, 50) + "...");
            System.out.println("Token expires in: " + initialTokens.expiresIn + " seconds\n");

            // ============================================================
            // STEP 2: Use initial access token to list S3 buckets
            // ============================================================
            System.out.println("=== STEP 2: Using Initial Access Token ===\n");

            RoleCredentials initialCredentials = getRoleCredentials(
                    initialTokens.accessToken, region, accountId, roleName);
            listS3Buckets(region, initialCredentials);

            // ============================================================
            // STEP 3: Wait a few seconds to simulate time passing
            // ============================================================
            System.out.println("\n=== STEP 3: Waiting 5 seconds before refreshing token ===\n");
            Thread.sleep(5000);

            // ============================================================
            // STEP 4: Refresh the access token using refresh token
            // ============================================================
            System.out.println("=== STEP 4: Refreshing Access Token ===\n");

            TokenResponse refreshedTokens = refreshAccessToken(
                    oidcEndpoint, clientInfo, initialTokens.refreshToken);

            System.out.println("Refreshed Access Token: " + refreshedTokens.accessToken.substring(0, 50) + "...");
            if (refreshedTokens.refreshToken != null) {
                System.out.println("New Refresh Token: " + refreshedTokens.refreshToken.substring(0, 50) + "...");
            } else {
                System.out.println("Refresh Token: (unchanged - reuse previous)");
            }
            System.out.println("Token expires in: " + refreshedTokens.expiresIn + " seconds\n");

            // ============================================================
            // STEP 5: Use refreshed access token to list S3 buckets again
            // ============================================================
            System.out.println("=== STEP 5: Using Refreshed Access Token ===\n");

            RoleCredentials refreshedCredentials = getRoleCredentials(
                    refreshedTokens.accessToken, region, accountId, roleName);
            listS3Buckets(region, refreshedCredentials);

            System.out.println("\n=== Refresh Token Flow Complete! ===");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Registers a client with AWS SSO OIDC for Authorization Code flow.
     */
    private static RegisterClientResponse registerClient(String oidcEndpoint, String issuerUrl) throws IOException {
        HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(
                request -> request.setParser(new JsonObjectParser(JSON_FACTORY)));

        Map<String, Object> data = new HashMap<>();
        data.put("clientName", "my-java-app-refresh-token");
        data.put("clientType", "public");
        data.put("issuerUrl", issuerUrl);
        data.put("grantTypes", new String[] { "authorization_code", "refresh_token" });
        data.put("scopes", new String[] { "sso:account:access" });
        data.put("redirectUris", new String[] { REDIRECT_URI });

        HttpRequest request = requestFactory.buildPostRequest(
                new GenericUrl(oidcEndpoint + "/client/register"),
                new JsonHttpContent(JSON_FACTORY, data));

        request.getHeaders().setContentType("application/json");

        HttpResponse response = request.execute();
        return response.parseAs(RegisterClientResponse.class);
    }

    /**
     * Authenticates using Authorization Code flow and returns the full token response.
     */
    private static TokenResponse authenticateWithAuthorizationCode(
            String oidcEndpoint,
            ClientInfo clientInfo,
            String startUrl) throws Exception {

        // Generate PKCE code verifier and challenge
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);
        String state = generateState();

        // Start local HTTP server to receive the callback
        CompletableFuture<String> authCodeFuture = new CompletableFuture<>();
        HttpServer server = startCallbackServer(authCodeFuture, state);

        try {
            // Build authorization URL and open browser
            String authorizationUrl = buildAuthorizationUrl(
                    oidcEndpoint,
                    clientInfo.clientId,
                    REDIRECT_URI,
                    codeChallenge,
                    state,
                    startUrl);

            System.out.println("===========================================");
            System.out.println("Opening browser for authentication...");
            System.out.println("Authorization URL: " + authorizationUrl);
            System.out.println("===========================================\n");

            // Open browser
            if (java.awt.Desktop.isDesktopSupported()) {
                try {
                    java.awt.Desktop.getDesktop().browse(java.net.URI.create(authorizationUrl));
                } catch (Exception e) {
                    System.out.println("Could not open browser automatically. Please visit the URL above.");
                }
            }

            // Wait for authorization code from callback
            System.out.println("Waiting for authorization callback...");
            String authorizationCode = authCodeFuture.get(5, TimeUnit.MINUTES);
            System.out.println("Authorization code received!\n");

            // Exchange authorization code for tokens
            TokenResponse tokenResponse = exchangeCodeForTokens(
                    oidcEndpoint,
                    clientInfo,
                    authorizationCode,
                    codeVerifier);

            System.out.println("Initial authentication successful!\n");
            return tokenResponse;

        } finally {
            server.stop(0);
        }
    }

    /**
     * Exchanges the authorization code for tokens (returns full response with refresh token).
     */
    private static TokenResponse exchangeCodeForTokens(
            String oidcEndpoint,
            ClientInfo clientInfo,
            String authorizationCode,
            String codeVerifier) throws IOException {

        HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(
                request -> request.setParser(new JsonObjectParser(JSON_FACTORY)));

        Map<String, String> data = new HashMap<>();
        data.put("clientId", clientInfo.clientId);
        data.put("clientSecret", clientInfo.clientSecret);
        data.put("grantType", "authorization_code");
        data.put("code", authorizationCode);
        data.put("redirectUri", REDIRECT_URI);
        data.put("codeVerifier", codeVerifier);

        HttpRequest request = requestFactory.buildPostRequest(
                new GenericUrl(oidcEndpoint + "/token"),
                new JsonHttpContent(JSON_FACTORY, data));

        request.getHeaders().setContentType("application/json");

        HttpResponse response = request.execute();
        return response.parseAs(TokenResponse.class);
    }

    /**
     * Refreshes the access token using a refresh token.
     * This is the key method demonstrating the Refresh Token Grant flow.
     */
    private static TokenResponse refreshAccessToken(
            String oidcEndpoint,
            ClientInfo clientInfo,
            String refreshToken) throws IOException {

        System.out.println("Requesting new access token using refresh token...");

        HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(
                request -> request.setParser(new JsonObjectParser(JSON_FACTORY)));

        Map<String, String> data = new HashMap<>();
        data.put("clientId", clientInfo.clientId);
        data.put("clientSecret", clientInfo.clientSecret);
        data.put("grantType", "refresh_token");
        data.put("refreshToken", refreshToken);

        HttpRequest request = requestFactory.buildPostRequest(
                new GenericUrl(oidcEndpoint + "/token"),
                new JsonHttpContent(JSON_FACTORY, data));

        request.getHeaders().setContentType("application/json");

        HttpResponse response = request.execute();
        TokenResponse tokenResponse = response.parseAs(TokenResponse.class);

        System.out.println("Token refresh successful!\n");
        return tokenResponse;
    }

    /**
     * Generates a cryptographically random code verifier for PKCE.
     */
    private static String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    /**
     * Generates the code challenge from the code verifier using SHA-256.
     */
    private static String generateCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    /**
     * Generates a random state parameter for CSRF protection.
     */
    private static String generateState() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] state = new byte[16];
        secureRandom.nextBytes(state);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(state);
    }

    /**
     * Builds the authorization URL for the OAuth 2.0 Authorization Code flow.
     */
    private static String buildAuthorizationUrl(
            String oidcEndpoint,
            String clientId,
            String redirectUri,
            String codeChallenge,
            String state,
            String startUrl) {

        return oidcEndpoint + "/authorize?" +
                "response_type=code" +
                "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8) +
                "&code_challenge=" + URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8) +
                "&code_challenge_method=S256" +
                "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8) +
                "&scopes=" + URLEncoder.encode("sso:account:access", StandardCharsets.UTF_8) +
                "&start_url=" + URLEncoder.encode(startUrl, StandardCharsets.UTF_8);
    }

    /**
     * Starts a local HTTP server to receive the OAuth callback.
     */
    private static HttpServer startCallbackServer(CompletableFuture<String> authCodeFuture, String expectedState)
            throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(CALLBACK_PORT), 0);

        server.createContext("/oauth/callback", exchange -> {
            try {
                String query = exchange.getRequestURI().getQuery();
                Map<String, String> params = parseQueryString(query);

                String code = params.get("code");
                String state = params.get("state");
                String error = params.get("error");

                String responseText;
                int statusCode;

                if (error != null) {
                    responseText = "Authentication failed: " + error;
                    statusCode = 400;
                    authCodeFuture.completeExceptionally(
                            new IOException("Authentication failed: " + error));
                } else if (code == null) {
                    responseText = "No authorization code received";
                    statusCode = 400;
                    authCodeFuture.completeExceptionally(
                            new IOException("No authorization code received"));
                } else if (!expectedState.equals(state)) {
                    responseText = "State mismatch - possible CSRF attack";
                    statusCode = 400;
                    authCodeFuture.completeExceptionally(
                            new IOException("State mismatch - possible CSRF attack"));
                } else {
                    responseText = "Authentication successful! You can close this window.";
                    statusCode = 200;
                    authCodeFuture.complete(code);
                }

                sendResponse(exchange, statusCode, responseText);
            } catch (Exception e) {
                authCodeFuture.completeExceptionally(e);
                sendResponse(exchange, 500, "Internal error: " + e.getMessage());
            }
        });

        server.setExecutor(null);
        server.start();
        System.out.println("Callback server started on port " + CALLBACK_PORT);
        return server;
    }

    /**
     * Parses a query string into a map of parameters.
     */
    private static Map<String, String> parseQueryString(String query) {
        Map<String, String> params = new HashMap<>();
        if (query != null) {
            for (String param : query.split("&")) {
                String[] pair = param.split("=", 2);
                if (pair.length == 2) {
                    params.put(pair[0], java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
                }
            }
        }
        return params;
    }

    /**
     * Sends an HTTP response.
     */
    private static void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
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

        System.out.println("AWS Credentials obtained:");
        System.out.println("  Access Key: " + credentials.accessKeyId);
        System.out.println("  Expiration: " + credentials.expiration);

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
            System.out.println("S3 Buckets (count: " + listBucketsResponse.buckets().size() + "):");
            listBucketsResponse.buckets().stream().limit(5).forEach(bucket ->
                System.out.println("  - " + bucket.name()));
            if (listBucketsResponse.buckets().size() > 5) {
                System.out.println("  ... and " + (listBucketsResponse.buckets().size() - 5) + " more");
            }
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

package com.example.awssso;

import software.amazon.awssdk.services.ssooidc.SsoOidcClient;
import software.amazon.awssdk.services.ssooidc.model.*;
import software.amazon.awssdk.services.sso.SsoClient;
import software.amazon.awssdk.services.sso.model.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
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
 * AWS SSO authentication using AWS SDK v2.
 *
 * This example demonstrates the OAuth 2.0 Refresh Token Grant flow.
 * It first authenticates using Authorization Code flow to obtain tokens,
 * then demonstrates refreshing the access token using the refresh token.
 */
public class App {

    private static final int CALLBACK_PORT = 65500;
    // callback url needs to use /oauth/callback!
    private static final String REDIRECT_URI = "http://127.0.0.1:" + CALLBACK_PORT + "/oauth/callback";

    /**
     * Holds the token response including access and refresh tokens.
     */
    public static class TokenInfo {
        public final String accessToken;
        public final String refreshToken;
        public final Integer expiresIn;

        public TokenInfo(String accessToken, String refreshToken, Integer expiresIn) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.expiresIn = expiresIn;
        }
    }

    /**
     * Holds the client registration info needed for token refresh.
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
            Region awsRegion = Region.of(region);

            try (SsoOidcClient oidcClient = SsoOidcClient.builder()
                    .region(awsRegion)
                    .build()) {

                // ============================================================
                // STEP 1: Initial authentication using Authorization Code flow
                // ============================================================
                System.out.println("=== STEP 1: Initial Authentication ===\n");

                // Register client (needed for both initial auth and refresh)
                ClientInfo clientInfo = registerClient(oidcClient, issuerUrl);

                // Authenticate and get initial tokens
                TokenInfo initialTokens = authenticateWithAuthorizationCode(
                        oidcClient, clientInfo, startUrl, region);

                System.out.println("Initial Access Token: " + initialTokens.accessToken.substring(0, 50) + "...");
                System.out.println("Refresh Token: " + initialTokens.refreshToken.substring(0, 50) + "...");
                System.out.println("Token expires in: " + initialTokens.expiresIn + " seconds\n");

                // ============================================================
                // STEP 2: Use initial access token to list S3 buckets
                // ============================================================
                System.out.println("=== STEP 2: Using Initial Access Token ===\n");

                RoleCredentials initialCredentials = returnRoleCredentials(
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

                TokenInfo refreshedTokens = refreshAccessToken(oidcClient, clientInfo, initialTokens.refreshToken);

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

                RoleCredentials refreshedCredentials = returnRoleCredentials(
                        refreshedTokens.accessToken, region, accountId, roleName);
                listS3Buckets(region, refreshedCredentials);

                System.out.println("\n=== Refresh Token Flow Complete! ===");
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Registers a client with AWS SSO OIDC.
     */
    private static ClientInfo registerClient(SsoOidcClient oidcClient, String issuerUrl) {
        System.out.println("Registering client...");

        RegisterClientResponse registerResponse = oidcClient.registerClient(
                RegisterClientRequest.builder()
                        .clientName("my-java-app-refresh-token")
                        .clientType("public")
                        .issuerUrl(issuerUrl)
                        .grantTypes("authorization_code", "refresh_token")
                        .scopes("sso:account:access")
                        .redirectUris(REDIRECT_URI)
                        .build());

        System.out.println("Client registered successfully");
        System.out.println("Client ID: " + registerResponse.clientId() + "\n");

        return new ClientInfo(registerResponse.clientId(), registerResponse.clientSecret());
    }

    /**
     * Authenticates using Authorization Code flow and returns both access and refresh tokens.
     */
    private static TokenInfo authenticateWithAuthorizationCode(
            SsoOidcClient oidcClient,
            ClientInfo clientInfo,
            String startUrl,
            String region) throws Exception {

        // Generate PKCE code verifier and challenge
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);
        String state = generateState();

        // Start local HTTP server to receive the callback
        CompletableFuture<String> authCodeFuture = new CompletableFuture<>();
        HttpServer server = startCallbackServer(authCodeFuture, state);

        try {
            // Build authorization URL and open browser
            String oidcEndpoint = String.format("https://oidc.%s.amazonaws.com", region);
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
            CreateTokenResponse tokenResponse = oidcClient.createToken(
                    CreateTokenRequest.builder()
                            .clientId(clientInfo.clientId)
                            .clientSecret(clientInfo.clientSecret)
                            .grantType("authorization_code")
                            .code(authorizationCode)
                            .redirectUri(REDIRECT_URI)
                            .codeVerifier(codeVerifier)
                            .build());

            System.out.println("Initial authentication successful!\n");

            return new TokenInfo(
                    tokenResponse.accessToken(),
                    tokenResponse.refreshToken(),
                    tokenResponse.expiresIn());

        } finally {
            server.stop(0);
        }
    }

    /**
     * Refreshes the access token using a refresh token.
     * This is the key method demonstrating the Refresh Token Grant flow.
     */
    private static TokenInfo refreshAccessToken(
            SsoOidcClient oidcClient,
            ClientInfo clientInfo,
            String refreshToken) {

        System.out.println("Requesting new access token using refresh token...");

        CreateTokenResponse tokenResponse = oidcClient.createToken(
                CreateTokenRequest.builder()
                        .clientId(clientInfo.clientId)
                        .clientSecret(clientInfo.clientSecret)
                        .grantType("refresh_token")
                        .refreshToken(refreshToken)
                        .build());

        System.out.println("Token refresh successful!\n");

        return new TokenInfo(
                tokenResponse.accessToken(),
                tokenResponse.refreshToken(), // May be null if server doesn't rotate refresh tokens
                tokenResponse.expiresIn());
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
                    params.put(pair[0], URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
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
    public static RoleCredentials returnRoleCredentials(String accessToken, String region, String accountId,
            String roleName) {
        Region awsRegion = Region.of(region);

        try (SsoClient ssoClient = SsoClient.builder()
                .region(awsRegion)
                .build()) {

            GetRoleCredentialsResponse credentialsResponse = ssoClient.getRoleCredentials(
                    GetRoleCredentialsRequest.builder()
                            .accountId(accountId)
                            .roleName(roleName)
                            .accessToken(accessToken)
                            .build());

            RoleCredentials credentials = credentialsResponse.roleCredentials();
            System.out.println("AWS Credentials obtained:");
            System.out.println("  Access Key: " + credentials.accessKeyId());
            System.out.println("  Expiration: " + credentials.expiration());

            return credentials;
        } catch (Exception e) {
            throw new RuntimeException("Failed to get role credentials", e);
        }
    }

    /**
     * Lists S3 buckets to verify the credentials work.
     */
    public static void listS3Buckets(String region, RoleCredentials credentials) {
        Region awsRegion = Region.of(region);

        S3Client s3Client = S3Client.builder()
                .region(awsRegion)
                .credentialsProvider(() -> software.amazon.awssdk.auth.credentials.AwsSessionCredentials.create(
                        credentials.accessKeyId(),
                        credentials.secretAccessKey(),
                        credentials.sessionToken()))
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
}

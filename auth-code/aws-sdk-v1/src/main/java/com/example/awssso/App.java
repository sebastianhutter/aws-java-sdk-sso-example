package com.example.awssso;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.sso.AWSSSO;
import com.amazonaws.services.sso.AWSSSOClient;
import com.amazonaws.services.sso.model.GetRoleCredentialsRequest;
import com.amazonaws.services.sso.model.GetRoleCredentialsResult;
import com.amazonaws.services.sso.model.RoleCredentials;
import com.amazonaws.services.ssooidc.AWSSSOOIDC;
import com.amazonaws.services.ssooidc.AWSSSOOIDCClientBuilder;
import com.amazonaws.services.ssooidc.model.*;

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
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * AWS SSO authentication using AWS SDK v1.
 *
 * This example demonstrates how to authenticate with AWS IAM Identity Center
 * using the OAuth 2.0 Authorization Code Grant flow with PKCE (RFC 7636).
 */
public class App {

    private static final int CALLBACK_PORT = 8080;
    private static final String REDIRECT_URI = "http://localhost:" + CALLBACK_PORT + "/callback";

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
            // Authenticate and receive the access token
            String accessToken = authenticate(startUrl, region);

            // Get the role credentials
            RoleCredentials credentials = returnRoleCredentials(accessToken, region, accountId, roleName);

            // Verify credentials by listing S3 buckets
            listS3Buckets(region, credentials);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Authenticates with AWS SSO using the Authorization Code Grant flow with PKCE.
     */
    public static String authenticate(String startUrl, String region) throws Exception {
        AWSSSOOIDC oidcClient = AWSSSOOIDCClientBuilder.standard()
                .withRegion(region)
                .build();

        try {
            // Step 1: Register the client with redirect URI for Authorization Code flow
            System.out.println("Registering client...");
            RegisterClientRequest registerRequest = new RegisterClientRequest()
                    .withClientName("my-java-app-auth-code")
                    .withClientType("public")
                    .withGrantTypes(Arrays.asList("authorization_code", "refresh_token"))
                    .withRedirectUris(Arrays.asList(REDIRECT_URI));

            RegisterClientResult registerResponse = oidcClient.registerClient(registerRequest);

            System.out.println("Client registered successfully");
            System.out.println("Client ID: " + registerResponse.getClientId());

            // Step 2: Generate PKCE code verifier and challenge
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = generateCodeChallenge(codeVerifier);
            String state = generateState();

            // Step 3: Start local HTTP server to receive the callback
            CompletableFuture<String> authCodeFuture = new CompletableFuture<>();
            HttpServer server = startCallbackServer(authCodeFuture, state);

            try {
                // Step 4: Build authorization URL and open browser
                String oidcEndpoint = String.format("https://oidc.%s.amazonaws.com", region);
                String authorizationUrl = buildAuthorizationUrl(
                        oidcEndpoint,
                        registerResponse.getClientId(),
                        REDIRECT_URI,
                        codeChallenge,
                        state,
                        startUrl);

                System.out.println("\n===========================================");
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

                // Step 5: Wait for authorization code from callback
                System.out.println("Waiting for authorization callback...");
                String authorizationCode = authCodeFuture.get(5, TimeUnit.MINUTES);
                System.out.println("Authorization code received!");

                // Step 6: Exchange authorization code for tokens using AWS SDK
                CreateTokenRequest tokenRequest = new CreateTokenRequest()
                        .withClientId(registerResponse.getClientId())
                        .withClientSecret(registerResponse.getClientSecret())
                        .withGrantType("authorization_code")
                        .withCode(authorizationCode)
                        .withRedirectUri(REDIRECT_URI)
                        .withCodeVerifier(codeVerifier);

                CreateTokenResult tokenResponse = oidcClient.createToken(tokenRequest);

                System.out.println("Authentication successful!\n");
                return tokenResponse.getAccessToken();

            } finally {
                // Stop the callback server
                server.stop(0);
            }
        } finally {
            oidcClient.shutdown();
        }
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

        server.createContext("/callback", exchange -> {
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
        AWSSSO ssoClient = AWSSSOClient.builder()
                .withRegion(region)
                .build();

        try {
            GetRoleCredentialsRequest credentialsRequest = new GetRoleCredentialsRequest()
                    .withAccountId(accountId)
                    .withRoleName(roleName)
                    .withAccessToken(accessToken);

            GetRoleCredentialsResult credentialsResponse = ssoClient.getRoleCredentials(credentialsRequest);

            RoleCredentials credentials = credentialsResponse.getRoleCredentials();
            System.out.println("AWS Credentials:");
            System.out.println("Access Key: " + credentials.getAccessKeyId());
            System.out.println("Secret Key: " + credentials.getSecretAccessKey());
            System.out.println("Session Token: " + credentials.getSessionToken());
            System.out.println("Expiration: " + credentials.getExpiration());

            return credentials;
        } catch (Exception e) {
            throw new RuntimeException("Failed to get role credentials", e);
        } finally {
            ssoClient.shutdown();
        }
    }

    /**
     * Lists S3 buckets to verify the credentials work.
     */
    public static void listS3Buckets(String region, RoleCredentials credentials) {
        BasicSessionCredentials awsCredentials = new BasicSessionCredentials(
                credentials.getAccessKeyId(),
                credentials.getSecretAccessKey(),
                credentials.getSessionToken());

        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(region)
                .withCredentials(new AWSStaticCredentialsProvider(awsCredentials))
                .build();

        try {
            System.out.println("\nS3 Buckets:");
            for (Bucket bucket : s3Client.listBuckets()) {
                System.out.println("- " + bucket.getName());
            }
        } catch (Exception e) {
            System.err.println("Failed to list S3 buckets: " + e.getMessage());
        } finally {
            s3Client.shutdown();
        }
    }
}

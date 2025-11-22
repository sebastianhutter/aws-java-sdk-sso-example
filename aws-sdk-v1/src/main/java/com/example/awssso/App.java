package com.example.awssso;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.sso.AWSSSO;
import com.amazonaws.services.sso.AWSSOClientBuilder;
import com.amazonaws.services.sso.model.GetRoleCredentialsRequest;
import com.amazonaws.services.sso.model.GetRoleCredentialsResult;
import com.amazonaws.services.sso.model.RoleCredentials;
import com.amazonaws.services.ssooidc.AWSSSOOIDC;
import com.amazonaws.services.ssooidc.AWSSSOOIDCClientBuilder;
import com.amazonaws.services.ssooidc.model.*;

public class App {

    public static void main(String[] args) {
        if (args.length != 4) {
            System.err.println("Usage: App <startUrl> <region> <accountId> <roleName>");
            System.err.println(
                    "Example: App https://d-1234567890.awsapps.com/start eu-central-1 123456789012 AdministratorAccess");
            System.exit(1);
        }

        // the start url of the AWS IAM Identity Center instance, usually in the format
        // https://d-<directory_id>.awsapps.com/start
        String startUrl = args[0];
        // the AWS region where the IAM Identity Center instance is hosted
        String region = args[1];
        // the AWS account ID for which to obtain role credentials
        String accountId = args[2];
        // the role name to assume in the specified AWS account, the role name needs to
        // match the AWS Identity Center permission set!
        String roleName = args[3];

        // authenticate and receive the token, with the token we can
        String token = authenticate(startUrl, region, accountId, roleName);
        // get the role credentials
        RoleCredentials credentials = returnRoleCredentials(token, region, accountId, roleName);

        listS3Buckets(region, credentials);

    }

    public static String authenticate(String startUrl, String region, String accountId, String roleName) {
        AWSSSOOIDC oidcClient = AWSSSOOIDCClientBuilder.standard()
                .withRegion(region)
                .build();

        try {
            // Step 1: Register the client
            RegisterClientRequest registerRequest = new RegisterClientRequest()
                    .withClientName("my-java-app")
                    .withClientType("public");

            RegisterClientResult registerResponse = oidcClient.registerClient(registerRequest);

            System.out.println("Client registered successfully");

            // Step 2: Start device authorization
            StartDeviceAuthorizationRequest deviceAuthRequest = new StartDeviceAuthorizationRequest()
                    .withClientId(registerResponse.getClientId())
                    .withClientSecret(registerResponse.getClientSecret())
                    .withStartUrl(startUrl);

            StartDeviceAuthorizationResult deviceAuthResponse = oidcClient.startDeviceAuthorization(deviceAuthRequest);

            // Step 3: Display the user code and URL
            System.out.println("\n===========================================");
            System.out.println("Please visit: " + deviceAuthResponse.getVerificationUriComplete());
            System.out.println("Verify access code: " + deviceAuthResponse.getUserCode());
            System.out.println("===========================================\n");

            // Step 3.1: Open the verification URL in the default browser (optional)
            if (java.awt.Desktop.isDesktopSupported()) {
                java.awt.Desktop.getDesktop()
                        .browse(java.net.URI.create(deviceAuthResponse.getVerificationUriComplete()));
            }

            // Step 4: Poll for token
            String accessToken = pollForToken(oidcClient,
                    registerResponse.getClientId(),
                    registerResponse.getClientSecret(),
                    deviceAuthResponse.getDeviceCode(),
                    deviceAuthResponse.getInterval());

            System.out.println("Authentication successful!\n");

            return accessToken;
        } catch (Exception e) {
            throw new RuntimeException("Authentication failed", e);
        } finally {
            oidcClient.shutdown();
        }
    }

    public static RoleCredentials returnRoleCredentials(String accessToken, String region, String accountId,
            String roleName) {

        // Step 5: Get role credentials
        AWSSSO ssoClient = AWSSOClientBuilder.standard()
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

    private static String pollForToken(AWSSSOOIDC oidcClient, String clientId,
            String clientSecret, String deviceCode, Integer interval) {
        int pollInterval = (interval != null ? interval : 5) * 1000;

        while (true) {
            try {
                Thread.sleep(pollInterval);

                CreateTokenRequest tokenRequest = new CreateTokenRequest()
                        .withClientId(clientId)
                        .withClientSecret(clientSecret)
                        .withGrantType("urn:ietf:params:oauth:grant-type:device_code")
                        .withDeviceCode(deviceCode);

                CreateTokenResult tokenResponse = oidcClient.createToken(tokenRequest);

                return tokenResponse.getAccessToken();

            } catch (AuthorizationPendingException e) {
                System.out.println("Waiting for authorization...");
            } catch (SlowDownException e) {
                System.out.println("Slowing down polling...");
                pollInterval += 5000;
            } catch (Exception e) {
                throw new RuntimeException("Failed to get token", e);
            }
        }
    }
}
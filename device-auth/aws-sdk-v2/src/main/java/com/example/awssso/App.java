package com.example.awssso;

import software.amazon.awssdk.services.ssooidc.SsoOidcClient;
import software.amazon.awssdk.services.ssooidc.model.*;
import software.amazon.awssdk.services.sso.SsoClient;
import software.amazon.awssdk.services.sso.model.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;

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
        Region awsRegion = Region.of(region);

        try (SsoOidcClient oidcClient = SsoOidcClient.builder()
                .region(awsRegion)
                .build()) {

            // Step 1: Register the client
            RegisterClientResponse registerResponse = oidcClient.registerClient(
                    RegisterClientRequest.builder()
                            .clientName("my-java-app")
                            .clientType("public")
                            .build());

            System.out.println("Client registered successfully");

            // Step 2: Start device authorization
            StartDeviceAuthorizationResponse deviceAuthResponse = oidcClient.startDeviceAuthorization(
                    StartDeviceAuthorizationRequest.builder()
                            .clientId(registerResponse.clientId())
                            .clientSecret(registerResponse.clientSecret())
                            .startUrl(startUrl)
                            .build());

            // Step 3: Display the user code and URL
            System.out.println("\n===========================================");
            System.out.println("Please visit: " + deviceAuthResponse.verificationUriComplete());
            System.out.println("Verify access code: " + deviceAuthResponse.userCode());
            System.out.println("===========================================\n");

            // Step 3.1: Open the verification URL in the default browser (optional)
            if (java.awt.Desktop.isDesktopSupported()) {
                java.awt.Desktop.getDesktop().browse(java.net.URI.create(deviceAuthResponse.verificationUriComplete()));
            }

            // Step 4: Poll for token
            String accessToken = pollForToken(oidcClient,
                    registerResponse.clientId(),
                    registerResponse.clientSecret(),
                    deviceAuthResponse.deviceCode(),
                    deviceAuthResponse.interval());

            System.out.println("Authentication successful!\n");

            return accessToken;
        } catch (Exception e) {
            throw new RuntimeException("Authentication failed", e);
        }
    }

    public static RoleCredentials returnRoleCredentials(String accessToken, String region, String accountId,
            String roleName) {

        // Step 5: Get role credentials
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
            System.out.println("AWS Credentials:");
            System.out.println("Access Key: " + credentials.accessKeyId());
            System.out.println("Secret Key: " + credentials.secretAccessKey());
            System.out.println("Session Token: " + credentials.sessionToken());
            System.out.println("Expiration: " + credentials.expiration());

            return credentials;
        } catch (Exception e) {
            throw new RuntimeException("Failed to get role credentials", e);
        }
    }

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
            System.out.println("\nS3 Buckets:");
            listBucketsResponse.buckets().forEach(bucket -> System.out.println("- " + bucket.name()));
        } catch (Exception e) {
            System.err.println("Failed to list S3 buckets: " + e.getMessage());
        } finally {
            s3Client.close();
        }
    }

    private static String pollForToken(SsoOidcClient oidcClient, String clientId,
            String clientSecret, String deviceCode, Integer interval) {
        int pollInterval = (interval != null ? interval : 5) * 1000;

        while (true) {
            try {
                Thread.sleep(pollInterval);

                CreateTokenResponse tokenResponse = oidcClient.createToken(
                        CreateTokenRequest.builder()
                                .clientId(clientId)
                                .clientSecret(clientSecret)
                                .grantType("urn:ietf:params:oauth:grant-type:device_code")
                                .deviceCode(deviceCode)
                                .build());

                return tokenResponse.accessToken();

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
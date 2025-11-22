# aws-sso-auth

This repository contains example code demonstrating authentication against AWS IAM Identity Center using the [AWS SDK for Java](https://aws.amazon.com/sdk-for-java/) v1 and v2, as well as the [Google OAuth Java Client](https://github.com/googleapis/google-oauth-java-client).

DISCLAIMER: This code was created with assistance from Claude Code and should not be used as-is for production-grade applications!

## Reference implementations

- [device-auth](./device-auth/): Reference implementation for "Device Authorization Grant (RFC 8628)", suitable for devices without interactive sessions (CLIs, etc.)
- [auth-code](./auth-code/): Reference implementation for "Authorization Code Grant with PKCE (RFC 7636)", suitable for interactive applications
- [refresh-code](./refresh-code/): Reference implementation for "Refresh Token Grant", demonstrating how to use refresh tokens for applications with long-running sessions
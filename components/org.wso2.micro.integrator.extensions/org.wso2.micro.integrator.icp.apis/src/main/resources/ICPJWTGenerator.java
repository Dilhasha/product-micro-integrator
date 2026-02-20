/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * Standalone JWT generator for ICP Internal API security testing.
 *
 * Generates tokens identical to HMACJWTTokenGenerator, validated by ICPJWTSecurityHandler.
 *
 * Usage:
 *   javac ICPJWTGenerator.java
 *   java ICPJWTGenerator <secret> [expiry_seconds]
 *
 * Or with the JAR:
 *   java -jar ICPJWTGenerator.jar <secret> [expiry_seconds]
 *
 * Example:
 *   java -jar ICPJWTGenerator.jar "my-secret-at-least-32-bytes-long!!" 3600
 *
 * Then call the ICP API:
 *   curl -k -H "Authorization: Bearer <token>" \
 *        "https://localhost:9164/icp/artifacts?type=api&name=MyAPI"
 */

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class ICPJWTGenerator {

    // Defaults match deployment.toml keys:
    //   icp_config.jwt_issuer         (default: icp-runtime-jwt-issuer)
    //   icp_config.jwt_audience       (default: icp-server)
    //   icp_config.jwt_scope          (default: runtime_agent)
    //   icp_config.jwt_expiry_seconds (default: 3600)
    private static final String DEFAULT_ISSUER   = "icp-runtime-jwt-issuer";
    private static final String DEFAULT_AUDIENCE = "icp-server";
    private static final String DEFAULT_SCOPE    = "runtime_agent";
    private static final long   DEFAULT_EXPIRY   = 3600L;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java -jar ICPJWTGenerator.jar <secret> [expiry_seconds]");
            System.err.println("       secret must be the exact value of icp_config.jwt_hmac_secret in deployment.toml");
            System.exit(1);
        }

        String secret        = args[0];
        long   expirySeconds = args.length > 1 ? Long.parseLong(args[1]) : DEFAULT_EXPIRY;

        long now = System.currentTimeMillis() / 1000;
        long exp = now + expirySeconds;

        System.out.println();
        System.out.println("=== ICP JWT Generator ===");
        System.out.println("Issuer   : " + DEFAULT_ISSUER);
        System.out.println("Audience : " + DEFAULT_AUDIENCE);
        System.out.println("Scope    : " + DEFAULT_SCOPE);
        System.out.println("iat      : " + now + "  (" + toUtc(now) + ")");
        System.out.println("exp      : " + exp  + "  (" + toUtc(exp)  + ")");
        System.out.println("TTL      : " + expirySeconds + " seconds");
        System.out.println();

        String token = generate(secret, DEFAULT_ISSUER, DEFAULT_AUDIENCE, DEFAULT_SCOPE, now, exp);

        System.out.println("Token:");
        System.out.println(token);
        System.out.println();
        System.out.println("curl command:");
        System.out.println("  curl -k -H \"Authorization: Bearer " + token + "\" \\");
        System.out.println("       \"https://localhost:9164/icp/artifacts?type=api&name=<artifact-name>\"");
        System.out.println();
    }

    /**
     * Generates an HS256-signed JWT identical to what HMACJWTTokenGenerator produces.
     * ICPJWTSecurityHandler validates:
     *   1. HMAC-SHA256 signature over "header.payload" using the configured secret
     *   2. exp claim is present, numeric, and in the future
     *
     * @param secret        Exact value of icp_config.jwt_hmac_secret in deployment.toml (>= 32 bytes)
     * @param issuer        icp_config.jwt_issuer
     * @param audience      icp_config.jwt_audience
     * @param scope         icp_config.jwt_scope
     * @param iatEpochSecs  Issued-at time (Unix seconds)
     * @param expEpochSecs  Expiry time (Unix seconds)
     */
    public static String generate(String secret, String issuer, String audience,
                                  String scope, long iatEpochSecs, long expEpochSecs) throws Exception {
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length < 32) {
            throw new IllegalArgumentException(
                "HMAC secret must be at least 32 bytes (256 bits). " +
                "Provided secret is only " + secretBytes.length + " bytes. " +
                "Check icp_config.jwt_hmac_secret in deployment.toml.");
        }

        // Header - fixed, matches HMACJWTTokenGenerator (HS256)
        String headerJson  = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

        // Payload - field names match HMACJWTTokenGenerator.generateToken()
        // Note: Nimbus serialises aud as a JSON array ["icp-server"]
        String payloadJson = "{"
            + "\"iss\":\"" + escapeJson(issuer)    + "\","
            + "\"aud\":[\"" + escapeJson(audience) + "\"],"
            + "\"exp\":"   + expEpochSecs           + ","
            + "\"iat\":"   + iatEpochSecs            + ","
            + "\"scope\":\"" + escapeJson(scope)    + "\""
            + "}";

        String header  = b64url(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = b64url(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signing = header + "." + payload;

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secretBytes, "HmacSHA256"));
        byte[] sig = mac.doFinal(signing.getBytes(StandardCharsets.UTF_8));

        return signing + "." + b64url(sig);
    }

    private static String b64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static String toUtc(long epochSeconds) {
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME
            .format(Instant.ofEpochSecond(epochSeconds).atOffset(ZoneOffset.UTC));
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}

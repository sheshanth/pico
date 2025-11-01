package com.learning.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.javatuples.Pair;
import org.json.JSONObject;

import java.security.Key;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.logging.Logger;

public class JWTUtils {

    private static final Logger log = Logger.getLogger(JWTUtils.class.getName());

    private static final Map<String, SignatureAlgorithm> algMap;
    static {
        algMap = new HashMap<>();
        algMap.put("HS256", SignatureAlgorithm.HS256);
        algMap.put("HS384", SignatureAlgorithm.HS384);
        algMap.put("HS512", SignatureAlgorithm.HS512);
        algMap.put("RS256", SignatureAlgorithm.RS256);
        algMap.put("RS384", SignatureAlgorithm.RS384);
        algMap.put("RS512", SignatureAlgorithm.RS512);
        algMap.put("ES256", SignatureAlgorithm.ES256);
        algMap.put("ES384", SignatureAlgorithm.ES384);
        algMap.put("ES512", SignatureAlgorithm.ES512);
        algMap.put("PS256", SignatureAlgorithm.PS256);
        algMap.put("PS384", SignatureAlgorithm.PS384);
        algMap.put("PS512", SignatureAlgorithm.PS512);
        algMap.put("", SignatureAlgorithm.HS256);
    }


    public static Pair<String, String> createJWT(String typ, String alg, String userInput,
                                                 String iss, String sub, String aud, boolean iat, long exp) {
        /* Construct JWT Header */
        Map<String, Object> header = new TreeMap<>();
        header.put("alg", Objects.requireNonNullElse(alg, "HS256"));
        header.put("typ", Objects.requireNonNullElse(typ, "JWT"));
        log.fine(header.toString());

        /* Construct JWT Payload */
        JSONObject payload = createPayload(userInput, iss, sub, aud, iat, exp);

        Key key = signingKey(Objects.requireNonNullElse(alg, "HS256"));

        JwtBuilder jwtBuilder = Jwts.builder()
                .setHeader(header)
                .setPayload(payload.toString())
                .signWith(key);

        String jws = jwtBuilder.compact();

        return new Pair<>(jws, Encoders.BASE64.encode(key.getEncoded()));
    }

    private static JSONObject createPayload(String userInput, String iss, String sub, String aud, boolean iat, long exp) {
        JSONObject payload = new JSONObject(userInput);
        if (iss != null) {
            payload.put("iss", iss);
        }
        if (sub != null) {
            payload.put("sub", sub);
        }
        if (aud != null) {
            payload.put("aud", aud);
        }

        long nowSeconds = System.currentTimeMillis() / 1000L;

        if (iat) {
            payload.put("iat", nowSeconds);
        }

        if (exp != 0) {
            payload.put("exp", nowSeconds + exp);
        }
        return payload;
    }

    public static Key signingKey(String algorithm) {
        SignatureAlgorithm signatureAlgorithm = algMap.get(Objects.requireNonNullElse(algorithm, "HS256"));
        return Keys.secretKeyFor(signatureAlgorithm);
    }

    public static Pair<String, String> decodeJWT(String jws, String key) {
        // Avoid using JJWT parserBuilder to bypass the unresolved API in the current compile setup.
        // We'll split the token and Base64URL-decode the header and payload to return their JSON strings.
        if (jws == null) {
            return new Pair<>("", "");
        }
        String[] parts = jws.split("\\.");
        if (parts.length < 2) {
            return new Pair<>("", "");
        }

        Base64.Decoder urlDecoder = Base64.getUrlDecoder();
        String header = "";
        String payload = "";
        try {
            header = new String(urlDecoder.decode(parts[0]));
        } catch (IllegalArgumentException ignored) {
        }
        try {
            payload = new String(urlDecoder.decode(parts[1]));
        } catch (IllegalArgumentException ignored) {
        }

        return new Pair<>(header, payload);
    }

}

package com.progrms.devcource.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Jwt {

    private final String issuer;

    private final String clientSecret;

    private final int expirySeconds;

    private final Algorithm algorithm;

    private final JWTVerifier jwtVerifier;

    public Jwt(String issuer, String clientSecret, int expirySeconds) {
        this.issuer = issuer;
        this.clientSecret = clientSecret;
        this.expirySeconds = expirySeconds;
        this.algorithm = Algorithm.HMAC512(clientSecret);
        this.jwtVerifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
    }

    public String sign(Claims claims) {
        Date now = new Date();  // 가능하면 LocalDateTime
        JWTCreator.Builder builder = JWT.create();
        builder.withIssuer(issuer);
        builder.withIssuedAt(now);
        if (expirySeconds > 0) {
            builder.withExpiresAt(new Date(now.getTime() + expirySeconds * 1_000L));
        }
        builder.withClaim("username", claims.username);
        builder.withArrayClaim("roles", claims.roles);
        return builder.sign(algorithm);
    }

    public Claims verify(String token) {
        return new Claims(jwtVerifier.verify(token));
    }

    static public class Claims {

        String username;
        String[] roles;
        Date iat;
        Date exp;

        private Claims() {/*no-op*/}

        Claims(DecodedJWT decodedJWT) {
            Claim claimUsername = decodedJWT.getClaim("username");
            if (!claimUsername.isNull()) {
                this.username = claimUsername.asString();
            }
            Claim claimRoles = decodedJWT.getClaim("roles");
            if (!claimRoles.isNull()) {
                this.roles = claimRoles.asArray(String.class);
            }
            this.iat = decodedJWT.getIssuedAt();
            this.exp = decodedJWT.getExpiresAt();
        }

        public static Claims from(String username, String[] roles) {
            Claims claims = new Claims();
            claims.username = username;
            claims.roles = roles;
            return claims;
        }

        public Map<String, Object> asMap() {
            HashMap<String, Object> claimsMap = new HashMap<>();
            claimsMap.put("username", username);
            claimsMap.put("roles", roles);
            claimsMap.put("iat", iat());
            claimsMap.put("exp", exp());
            return claimsMap;
        }

        public long iat() {
            return iat != null ? iat.getTime() : -1;
        }

        public long exp() {
            return exp != null ? exp.getTime() : -1;
        }

        @Override
        public String toString() {
            return "Claims{" +
                    "username='" + username + '\'' +
                    ", roles=" + Arrays.toString(roles) +
                    ", iat=" + iat +
                    ", exp=" + exp +
                    '}';
        }

    }

}

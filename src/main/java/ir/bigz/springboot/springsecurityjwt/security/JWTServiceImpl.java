package ir.bigz.springboot.springsecurityjwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JWTServiceImpl implements JWTService {

    @Value("${jwt.secret.key}")
    private String JWT_KEY;
    private static final long TOKEN_TIME = 1000 * 60 * 15;
    private static final long REFRESH_TOKEN_TIME = 1000 * 60 * 240;

    Logger log = LoggerFactory.getLogger(JWTServiceImpl.class);

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", userDetails.getAuthorities());
        var header = Jwts.header();
        header.setType("JWT");
        return Jwts.builder()
                .setHeader((Map<String, Object>) header)
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuer("bigZ")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_TIME))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        extraClaims.put("role", userDetails.getAuthorities());
        var header = Jwts.header();
        header.setType("JWT");
        return Jwts.builder()
                .setHeader((Map<String, Object>) header)
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuer("bigZ")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_TIME))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaim(token);
        if(Objects.nonNull(claims))
            return claimsResolvers.apply(claims);
        return null;
    }

    private Key getSignKey() {
        byte[] key = Decoders.BASE64.decode(JWT_KEY);
        return Keys.hmacShaKeyFor(key);
    }

    private Claims extractAllClaim(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
        }catch (Exception e){
            log.info(e.getMessage());
        }
        return null;
    }
}

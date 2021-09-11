package com.platzi.market.web.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JWTUtil {
    private static final String KEY = "platzi";

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder().setSubject(userDetails.getUsername()).setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 100 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.HS256, KEY).compact();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        return userDetails.getUsername().equals(extractUsername(token)) && !isTokenExpired(token);
    }

    //Extraemos el nombre de usuario del sujeto para validarlo
    public String extractUsername(String token) {
        return getClaims(token).getSubject();

    }

    //Consultamos si el token ya expiro, comparandolo con la fecha actual.
    public boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    //Verificamos la firma con getClaims, que toma el contenido del codigo
    public Claims getClaims(String token) {
        return Jwts.parser().setSigningKey(KEY).parseClaimsJws(token).getBody();
    }
}

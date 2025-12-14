package com.elitech.services;

import java.awt.RenderingHints.Key;
import java.util.Date;
import java.util.Set;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtService {
@Value("${jwt.secret}")
private String secret;
private final UserInfoService userInfoService; //D.I
public String generateToken(String username,long userId,Set<String> roles)
{
return Jwts.builder()
		.setSubject(username)
		.claim("userId", userId)
		.claim("roles", roles)
		.setIssuedAt(new Date())
		.setExpiration(new Date(System.currentTimeMillis()+1000* 60 *60 * 4))
		.signWith((java.security.Key) getSignKey(),SignatureAlgorithm.HS256)
		.compact();
}

private Key getSignKey()
{
byte[] keyBytes=Decoders.BASE64.decode(secret);
return (Key) Keys.hmacShaKeyFor(keyBytes);
}
private <T> T extractClaim(String token, Function<Claims,T> claimResolver)
{
	final Claims claims= extractAllClaims(token);
	return claimResolver.apply(claims);

}
private Claims extractAllClaims(String token)
{
 return Jwts.parserBuilder()
		 .setSigningKey( (java.security.Key) getSignKey())
		 .build()
		 .parseClaimsJws(token)
		 .getBody();

}

private Boolean isTokenExpired(String token)
{
return extractionExpiration(token).before(new Date());	
}
public Date extractionExpiration(String token)
{
	return extractClaim(token, Claims::getExpiration);
	}
public String extractionUserName(String token)
{
	return extractClaim(token, Claims::getSubject);
	}
public Boolean validateToken(String token , UserDetails userDetails)
{
final String userName= extractionUserName(token);	
return (userName.equals(userDetails.getUsername())&& !isTokenExpired(token));
}
}

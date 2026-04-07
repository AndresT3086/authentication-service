package com.logistics.authentication.infrastructure.adapter.out.security;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import com.logistics.authentication.application.port.out.JwtTokenProviderPort;
import com.logistics.authentication.domain.model.UserAccount;
import com.logistics.authentication.infrastructure.config.JwtProperties;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtTokenProviderAdapter implements JwtTokenProviderPort {

	private final JwtProperties jwtProperties;

	@Override
	public String createAccessToken(UserAccount user) {
		Instant now = Instant.now();
		Instant exp = now.plusSeconds(jwtProperties.getAccessTokenTtlSeconds());
		SecretKey key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));

		return Jwts.builder()
				.subject(user.getId().toString())
				.claim("email", user.getEmail())
				.claim("roles", user.getRoles())
				.issuedAt(Date.from(now))
				.expiration(Date.from(exp))
				.signWith(key)
				.compact();
	}

	@Override
	public long getAccessTokenTtlSeconds() {
		return jwtProperties.getAccessTokenTtlSeconds();
	}

	@Override
	public long getRefreshTokenTtlSeconds() {
		return jwtProperties.getRefreshTokenTtlSeconds();
	}
}

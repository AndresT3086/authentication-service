package com.logistics.authentication.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {

	/**
	 * Secreto HS256 (mínimo 256 bits recomendado en producción).
	 */
	private String secret = "change-me-in-production-use-long-random-secret-key-256bits!!";

	private long accessTokenTtlSeconds = 3600;

	/**
	 * TTL del refresh token opaco (segundos), p. ej. 7 días.
	 */
	private long refreshTokenTtlSeconds = 604800;
}

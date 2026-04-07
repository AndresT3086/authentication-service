package com.logistics.authentication.infrastructure.config;

import java.nio.charset.StandardCharsets;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

/**
 * Falla el arranque si el secreto JWT es demasiado corto para HS256 (OWASP / JJWT).
 */
@Component
@Profile("!test")
@RequiredArgsConstructor
public class JwtSecretStrengthValidator {

	private static final int MIN_SECRET_BYTES = 32;

	private final JwtProperties jwtProperties;

	@EventListener(ApplicationReadyEvent.class)
	public void validateSecretLength() {
		byte[] secret = jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8);
		if (secret.length < MIN_SECRET_BYTES) {
			throw new IllegalStateException(
					"JWT_SECRET / app.jwt.secret debe tener al menos " + MIN_SECRET_BYTES
							+ " bytes para HS256. Configure una variable de entorno segura en producción.");
		}
	}
}

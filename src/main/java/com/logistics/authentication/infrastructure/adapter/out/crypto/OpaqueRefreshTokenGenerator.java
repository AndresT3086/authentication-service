package com.logistics.authentication.infrastructure.adapter.out.crypto;

import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.stereotype.Component;

@Component
public class OpaqueRefreshTokenGenerator {

	private final SecureRandom random = new SecureRandom();

	/**
	 * Token opaco URL-safe (~43 caracteres); nunca se persiste en claro, solo su hash SHA-256.
	 */
	public String generate() {
		byte[] bytes = new byte[32];
		random.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}
}

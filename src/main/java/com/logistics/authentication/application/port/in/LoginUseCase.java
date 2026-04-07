package com.logistics.authentication.application.port.in;

import java.util.Set;

public interface LoginUseCase {

	LoginResult login(LoginCommand command);

	record LoginCommand(String email, String rawPassword) {
	}

	/**
	 * @param refreshToken       token opaco (solo en login y refresh; no es JWT)
	 * @param refreshExpiresInSeconds TTL del refresh en segundos
	 */
	record LoginResult(
			String accessToken,
			String tokenType,
			long expiresInSeconds,
			Set<String> roles,
			String refreshToken,
			long refreshExpiresInSeconds) {
	}
}

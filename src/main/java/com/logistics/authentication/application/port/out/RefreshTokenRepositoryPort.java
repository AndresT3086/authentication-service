package com.logistics.authentication.application.port.out;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistencia de refresh tokens opacos (solo hash en BD).
 */
public interface RefreshTokenRepositoryPort {

	Optional<RefreshTokenActive> findActiveByTokenHash(String sha256Hex, Instant now);

	void revokeAllForUser(UUID userId);

	UUID save(UUID userId, String tokenSha256Hex, Instant expiresAt);

	void revokeById(UUID id);

	record RefreshTokenActive(UUID id, UUID userId) {
	}
}

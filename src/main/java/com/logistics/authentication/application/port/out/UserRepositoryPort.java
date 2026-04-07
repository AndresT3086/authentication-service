package com.logistics.authentication.application.port.out;

import java.util.Optional;
import java.util.UUID;

import com.logistics.authentication.domain.model.UserAccount;

public interface UserRepositoryPort {

	Optional<UserAccount> findByEmail(String email);

	Optional<UserAccount> findById(UUID id);

	void resetFailedLogin(UUID userId);

	void registerFailedLogin(UUID userId, int newAttemptCount, java.time.Instant lockedUntilOrNull);
}

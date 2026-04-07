package com.logistics.authentication.infrastructure.adapter.out.persistence;

import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Component;

import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.model.UserAccount;
import com.logistics.authentication.infrastructure.adapter.out.persistence.mapper.UserMapper;
import com.logistics.authentication.infrastructure.adapter.out.persistence.repository.UserJpaRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class UserPersistenceAdapter implements UserRepositoryPort {

	private final UserJpaRepository userJpaRepository;
	private final UserMapper userMapper;

	@Override
	public Optional<UserAccount> findByEmail(String email) {
		return userJpaRepository.findByEmailIgnoreCase(email).map(userMapper::toDomain);
	}

	@Override
	public Optional<UserAccount> findById(UUID id) {
		return userJpaRepository.findById(id).map(userMapper::toDomain);
	}

	@Override
	public void resetFailedLogin(UUID userId) {
		userJpaRepository.resetFailedLogin(userId);
	}

	@Override
	public void registerFailedLogin(UUID userId, int newAttemptCount, java.time.Instant lockedUntilOrNull) {
		userJpaRepository.updateFailedLogin(userId, newAttemptCount, lockedUntilOrNull);
	}
}

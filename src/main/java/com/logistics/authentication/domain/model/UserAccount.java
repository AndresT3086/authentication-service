package com.logistics.authentication.domain.model;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import lombok.Builder;
import lombok.Value;

/**
 * Usuario del dominio (sin detalles de persistencia).
 */
@Value
@Builder
public class UserAccount {

	UUID id;
	String email;
	String passwordHash;
	Set<String> roles;
	boolean enabled;
	int failedLoginAttempts;
	Instant lockedUntil;

	public boolean isLocked(Instant now) {
		return lockedUntil != null && lockedUntil.isAfter(now);
	}
}

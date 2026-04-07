package com.logistics.authentication.application.port.out;

import java.util.UUID;

/**
 * Puerto saliente para auditoría de seguridad (invoca procedimiento en BD).
 */
public interface LoginAuditPort {

	void recordLoginAttempt(UUID userIdOrNull, String email, boolean success, String reasonOrNull);
}

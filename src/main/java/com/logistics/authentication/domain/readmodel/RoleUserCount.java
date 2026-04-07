package com.logistics.authentication.domain.readmodel;

/**
 * Resultado de consulta agregada: usuarios por rol (no trivial: join + group by).
 */
public record RoleUserCount(String roleName, long userCount) {
}

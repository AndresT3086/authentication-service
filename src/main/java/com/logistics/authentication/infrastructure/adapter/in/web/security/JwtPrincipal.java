package com.logistics.authentication.infrastructure.adapter.in.web.security;

/**
 * Principal autenticado extraído del JWT (sin consulta a BD en cada petición).
 */
public record JwtPrincipal(String userId, String email) {
}

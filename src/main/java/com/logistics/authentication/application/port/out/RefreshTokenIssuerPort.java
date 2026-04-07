package com.logistics.authentication.application.port.out;

/**
 * Generación de refresh tokens opacos y hash para persistencia (detalle en adaptador).
 */
public interface RefreshTokenIssuerPort {

	String newOpaqueToken();

	String sha256Hex(String plainToken);
}

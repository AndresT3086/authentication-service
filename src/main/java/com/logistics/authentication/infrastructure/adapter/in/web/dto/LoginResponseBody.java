package com.logistics.authentication.infrastructure.adapter.in.web.dto;

import java.util.Set;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Respuesta de login o refresh: JWT de acceso + refresh opaco")
public record LoginResponseBody(
		@Schema(description = "JWT de acceso") String accessToken,
		@Schema(example = "Bearer") String tokenType,
		@Schema(description = "Segundos hasta expiración del access token") long expiresIn,
		@Schema(description = "Roles RBAC incluidos en el access token") Set<String> roles,
		@Schema(description = "Refresh token opaco (no es JWT). Usar solo en POST /auth/refresh") String refreshToken,
		@Schema(description = "Segundos hasta expiración del refresh token") long refreshExpiresIn) {
}

package com.logistics.authentication.infrastructure.adapter.in.web.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Identidad actual derivada del JWT (sin consulta obligatoria a BD)")
public record MeResponseBody(
		@Schema(example = "33333333-3333-3333-3333-333333333333") String userId,
		@Schema(example = "admin@logistics.com") String email,
		@Schema(description = "Autoridades RBAC (prefijo ROLE_)") List<String> roles) {
}

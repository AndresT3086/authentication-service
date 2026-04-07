package com.logistics.authentication.infrastructure.adapter.in.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Renovación de access token mediante refresh opaco")
public record RefreshRequest(
		@NotBlank
		@Schema(description = "Refresh token devuelto en login o refresh anterior", example = "abc...") String refreshToken) {
}

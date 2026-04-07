package com.logistics.authentication.infrastructure.adapter.in.web.dto;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.swagger.v3.oas.annotations.media.Schema;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Error estandarizado de API")
public record ApiErrorResponse(
		@Schema(example = "AUTH_INVALID_CREDENTIALS") String errorCode,
		String message,
		List<String> details,
		String traceId) {
}

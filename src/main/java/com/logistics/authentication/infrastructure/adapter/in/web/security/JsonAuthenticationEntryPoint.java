package com.logistics.authentication.infrastructure.adapter.in.web.security;

import java.io.IOException;

import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.ApiErrorResponse;
import com.logistics.authentication.infrastructure.adapter.in.web.filter.TraceIdFilter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Respuesta 401 JSON alineada con {@link ApiErrorResponse} (sin cuerpo vacío).
 */
@Component
@RequiredArgsConstructor
public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private final ObjectMapper objectMapper;

	@Override
	public void commence(
			HttpServletRequest request,
			HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		String trace = firstNonBlank(MDC.get(TraceIdFilter.TRACE_ID_MDC), request.getHeader(TraceIdFilter.TRACE_ID_HEADER));
		var body = new ApiErrorResponse(
				"UNAUTHORIZED",
				"Se requiere autenticación (token Bearer válido)",
				null,
				trace);
		objectMapper.writeValue(response.getOutputStream(), body);
	}

	private static String firstNonBlank(String a, String b) {
		if (a != null && !a.isBlank()) {
			return a;
		}
		if (b != null && !b.isBlank()) {
			return b;
		}
		return null;
	}
}

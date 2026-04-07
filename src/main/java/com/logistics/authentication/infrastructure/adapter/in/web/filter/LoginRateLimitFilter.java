package com.logistics.authentication.infrastructure.adapter.in.web.filter;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.ApiErrorResponse;
import com.logistics.authentication.infrastructure.config.SecurityProperties;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Limita la frecuencia de POST /api/v1/auth/login por dirección IP (OWASP: fuerza bruta).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
@RequiredArgsConstructor
public class LoginRateLimitFilter extends OncePerRequestFilter {

	private static final long WINDOW_MS = 60_000L;

	private final SecurityProperties securityProperties;
	private final ObjectMapper objectMapper;

	private final ConcurrentHashMap<String, Deque<Long>> buckets = new ConcurrentHashMap<>();

	@Override
	protected void doFilterInternal(
			HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {
		String path = request.getServletPath();
		boolean authPost = HttpMethod.POST.matches(request.getMethod())
				&& ("/api/v1/auth/login".equals(path) || "/api/v1/auth/refresh".equals(path));
		if (!authPost) {
			filterChain.doFilter(request, response);
			return;
		}
		String ip = clientIp(request);
		long now = System.currentTimeMillis();
		int limit = Math.max(1, securityProperties.getLoginRateLimitPerMinute());
		Deque<Long> window = buckets.computeIfAbsent(ip, k -> new ArrayDeque<>());
		synchronized (window) {
			while (!window.isEmpty() && now - window.peekFirst() > WINDOW_MS) {
				window.pollFirst();
			}
			if (window.size() >= limit) {
				response.setStatus(429);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				String trace = request.getHeader(TraceIdFilter.TRACE_ID_HEADER);
				var body = new ApiErrorResponse(
						"RATE_LIMIT_EXCEEDED",
						"Demasiados intentos de login. Espere un minuto e intente de nuevo.",
						null,
						trace);
				objectMapper.writeValue(response.getOutputStream(), body);
				return;
			}
			window.addLast(now);
		}
		filterChain.doFilter(request, response);
	}

	private static String clientIp(HttpServletRequest request) {
		String xff = request.getHeader("X-Forwarded-For");
		if (xff != null && !xff.isBlank()) {
			return xff.split(",")[0].trim();
		}
		return request.getRemoteAddr() != null ? request.getRemoteAddr() : "unknown";
	}
}

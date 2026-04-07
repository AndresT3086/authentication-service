package com.logistics.authentication.infrastructure.adapter.in.web.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.util.AntPathMatcher;

import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import org.slf4j.MDC;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.ApiErrorResponse;
import com.logistics.authentication.infrastructure.adapter.in.web.filter.TraceIdFilter;
import com.logistics.authentication.infrastructure.config.JwtProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Valida JWT Bearer y rellena el contexto de seguridad (RBAC por claims).
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private static final AntPathMatcher MATCHER = new AntPathMatcher();

	private final JwtProperties jwtProperties;
	private final ObjectMapper objectMapper;

	/** No validar JWT en login ni documentación (evita 401 si se envía un Bearer erróneo en /login). */
	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		String path = request.getServletPath();
		return MATCHER.match("/api/v1/auth/login", path)
				|| MATCHER.match("/api/v1/auth/refresh", path)
				|| MATCHER.match("/v3/api-docs/**", path)
				|| MATCHER.match("/swagger-ui/**", path)
				|| MATCHER.match("/swagger-ui.html", path);
	}

	@Override
	protected void doFilterInternal(
			@NonNull HttpServletRequest request,
			@NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain) throws ServletException, IOException {
		String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (header == null || !header.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}
		String token = header.substring(7);
		try {
			SecretKey key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
			Claims claims = Jwts.parser()
					.verifyWith(key)
					.build()
					.parseSignedClaims(token)
					.getPayload();

			String userId = claims.getSubject();
			String email = claims.get("email", String.class);
			List<String> roles = extractRoles(claims.get("roles"));
			Collection<GrantedAuthority> authorities = new ArrayList<>();
			for (String r : roles) {
				if (r != null && !r.isBlank()) {
					authorities.add(new SimpleGrantedAuthority(r.startsWith("ROLE_") ? r : "ROLE_" + r));
				}
			}
			Authentication auth = new UsernamePasswordAuthenticationToken(
					new JwtPrincipal(userId, email),
					null,
					authorities);
			SecurityContextHolder.getContext().setAuthentication(auth);
		}
		catch (JwtException | IllegalArgumentException ex) {
			SecurityContextHolder.clearContext();
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			String trace = firstNonBlank(MDC.get(TraceIdFilter.TRACE_ID_MDC), request.getHeader(TraceIdFilter.TRACE_ID_HEADER));
			var body = new ApiErrorResponse(
					"INVALID_OR_EXPIRED_TOKEN",
					"Token Bearer inválido o expirado",
					null,
					trace);
			objectMapper.writeValue(response.getOutputStream(), body);
			return;
		}
		filterChain.doFilter(request, response);
	}

	private static List<String> extractRoles(Object raw) {
		if (raw == null) {
			return List.of();
		}
		if (raw instanceof Collection<?> c) {
			List<String> out = new ArrayList<>();
			for (Object o : c) {
				if (o != null) {
					out.add(o.toString());
				}
			}
			return out;
		}
		return List.of(raw.toString());
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

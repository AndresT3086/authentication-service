package com.logistics.authentication.infrastructure.adapter.in.web.filter;

import java.io.IOException;
import java.util.UUID;

import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TraceIdFilter extends OncePerRequestFilter {

	public static final String TRACE_ID_HEADER = "X-Trace-Id";
	public static final String TRACE_ID_MDC = "traceId";

	@Override
	protected void doFilterInternal(
			HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {
		String traceId = request.getHeader(TRACE_ID_HEADER);
		if (traceId == null || traceId.isBlank()) {
			traceId = UUID.randomUUID().toString();
		}
		MDC.put(TRACE_ID_MDC, traceId);
		response.setHeader(TRACE_ID_HEADER, traceId);
		try {
			filterChain.doFilter(request, response);
		}
		finally {
			MDC.remove(TRACE_ID_MDC);
		}
	}
}

package com.logistics.authentication.infrastructure.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.cors")
public class CorsProperties {

	/**
	 * Orígenes permitidos separados por coma (CORS restrictivo).
	 */
	private String allowedOrigins = "http://localhost:3000,http://localhost:5173";

	public List<String> allowedOriginList() {
		return Arrays.stream(allowedOrigins.split(","))
				.map(String::trim)
				.filter(s -> !s.isEmpty())
				.toList();
	}
}

package com.logistics.authentication.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

	/**
	 * HSTS: solo activar detrás de HTTPS (producción).
	 */
	private boolean hstsEnabled;

	/**
	 * Máximo de peticiones POST /login por IP y ventana de un minuto (mitigación fuerza bruta).
	 */
	private int loginRateLimitPerMinute = 30;
}

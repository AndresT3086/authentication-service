package com.logistics.authentication.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;

@Configuration
public class OpenApiConfig {

	@Bean
	public OpenAPI authenticationOpenApi() {
		return new OpenAPI()
				.info(new Info()
						.title("Authentication API")
						.description("Contrato OpenAPI del microservicio de autenticación (login JWT). Versión v1.")
						.version("v1"))
				.components(new Components().addSecuritySchemes("bearer-jwt",
						new SecurityScheme()
								.type(SecurityScheme.Type.HTTP)
								.scheme("bearer")
								.bearerFormat("JWT")));
	}
}

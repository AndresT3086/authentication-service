package com.logistics.authentication.infrastructure.adapter.in.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.hateoas.HypermediaAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logistics.authentication.application.port.in.LoginUseCase;
import com.logistics.authentication.application.port.in.LoginUseCase.LoginResult;
import com.logistics.authentication.application.port.in.RefreshTokenUseCase;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.LoginRequest;

@WebMvcTest(
		controllers = AuthController.class,
		excludeAutoConfiguration = { SecurityAutoConfiguration.class, UserDetailsServiceAutoConfiguration.class })
@Import(HypermediaAutoConfiguration.class)
class AuthControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private ObjectMapper objectMapper;

	@MockBean
	private LoginUseCase loginUseCase;

	@MockBean
	private RefreshTokenUseCase refreshTokenUseCase;

	@Test
	void login_returns200AndBody() throws Exception {
		when(loginUseCase.login(any()))
				.thenReturn(new LoginResult("tok", "Bearer", 3600, Set.of("ROLE_ADMIN"), "refresh-opaque", 604800L));

		var req = new LoginRequest("admin@logistics.com", "password123");

		mockMvc.perform(post("/api/v1/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(req)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.accessToken").value("tok"))
				.andExpect(jsonPath("$.tokenType").value("Bearer"))
				.andExpect(jsonPath("$.expiresIn").value(3600))
				.andExpect(jsonPath("$.roles[0]").value("ROLE_ADMIN"))
				.andExpect(jsonPath("$.refreshToken").value("refresh-opaque"))
				.andExpect(jsonPath("$.refreshExpiresIn").value(604800));
	}
}

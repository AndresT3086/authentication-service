package com.logistics.authentication.application.service;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.logistics.authentication.application.port.in.LoginUseCase;
import com.logistics.authentication.application.port.out.JwtTokenProviderPort;
import com.logistics.authentication.application.port.out.LoginAuditPort;
import com.logistics.authentication.application.port.out.PasswordEncoderPort;
import com.logistics.authentication.application.port.out.RefreshTokenIssuerPort;
import com.logistics.authentication.application.port.out.RefreshTokenRepositoryPort;
import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.domain.model.UserAccount;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class LoginService implements LoginUseCase {

	private static final int MAX_FAILED_ATTEMPTS = 5;
	private static final int LOCK_MINUTES = 15;

	private final UserRepositoryPort users;
	private final PasswordEncoderPort passwordEncoder;
	private final JwtTokenProviderPort jwtTokenProvider;
	private final LoginAuditPort loginAudit;
	private final RefreshTokenRepositoryPort refreshTokens;
	private final RefreshTokenIssuerPort refreshTokenIssuer;
	private final Clock clock;

	@Override
	@Transactional
	public LoginResult login(LoginCommand command) {
		Instant now = clock.instant();
		var userOpt = users.findByEmail(command.email().trim().toLowerCase());

		if (userOpt.isEmpty()) {
			loginAudit.recordLoginAttempt(null, command.email(), false, "USER_NOT_FOUND");
			throw new AuthenticationDomainException("AUTH_INVALID_CREDENTIALS", "Credenciales inválidas");
		}

		UserAccount user = userOpt.get();

		if (!user.isEnabled()) {
			loginAudit.recordLoginAttempt(user.getId(), user.getEmail(), false, "USER_DISABLED");
			throw new AuthenticationDomainException("AUTH_ACCOUNT_DISABLED", "Cuenta deshabilitada");
		}

		if (user.isLocked(now)) {
			loginAudit.recordLoginAttempt(user.getId(), user.getEmail(), false, "ACCOUNT_LOCKED");
			throw new AuthenticationDomainException("AUTH_ACCOUNT_LOCKED", "Cuenta bloqueada temporalmente");
		}

		boolean passwordOk = passwordEncoder.matches(command.rawPassword(), user.getPasswordHash());
		if (!passwordOk) {
			int next = user.getFailedLoginAttempts() + 1;
			Instant lockUntil = null;
			if (next >= MAX_FAILED_ATTEMPTS) {
				lockUntil = now.plus(LOCK_MINUTES, ChronoUnit.MINUTES);
			}
			users.registerFailedLogin(user.getId(), next, lockUntil);
			loginAudit.recordLoginAttempt(user.getId(), user.getEmail(), false, "BAD_PASSWORD");
			throw new AuthenticationDomainException("AUTH_INVALID_CREDENTIALS", "Credenciales inválidas");
		}

		users.resetFailedLogin(user.getId());
		String token = jwtTokenProvider.createAccessToken(user);
		loginAudit.recordLoginAttempt(user.getId(), user.getEmail(), true, null);

		refreshTokens.revokeAllForUser(user.getId());
		String refreshPlain = refreshTokenIssuer.newOpaqueToken();
		Instant refreshExp = now.plusSeconds(jwtTokenProvider.getRefreshTokenTtlSeconds());
		refreshTokens.save(user.getId(), refreshTokenIssuer.sha256Hex(refreshPlain), refreshExp);

		return new LoginResult(
				token,
				"Bearer",
				jwtTokenProvider.getAccessTokenTtlSeconds(),
				user.getRoles(),
				refreshPlain,
				jwtTokenProvider.getRefreshTokenTtlSeconds());
	}
}

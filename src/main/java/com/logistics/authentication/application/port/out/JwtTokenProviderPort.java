package com.logistics.authentication.application.port.out;

import com.logistics.authentication.domain.model.UserAccount;

public interface JwtTokenProviderPort {

	String createAccessToken(UserAccount user);

	long getAccessTokenTtlSeconds();

	long getRefreshTokenTtlSeconds();
}

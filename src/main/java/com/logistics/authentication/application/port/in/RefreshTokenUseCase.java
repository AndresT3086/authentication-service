package com.logistics.authentication.application.port.in;

public interface RefreshTokenUseCase {

	LoginUseCase.LoginResult refresh(RefreshCommand command);

	record RefreshCommand(String rawRefreshToken) {
	}
}

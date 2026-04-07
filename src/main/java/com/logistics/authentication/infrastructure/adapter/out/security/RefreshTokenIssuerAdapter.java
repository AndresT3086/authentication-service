package com.logistics.authentication.infrastructure.adapter.out.security;

import org.springframework.stereotype.Component;

import com.logistics.authentication.application.port.out.RefreshTokenIssuerPort;
import com.logistics.authentication.infrastructure.adapter.out.crypto.OpaqueRefreshTokenGenerator;
import com.logistics.authentication.infrastructure.adapter.out.crypto.Sha256Hex;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class RefreshTokenIssuerAdapter implements RefreshTokenIssuerPort {

	private final OpaqueRefreshTokenGenerator generator;

	@Override
	public String newOpaqueToken() {
		return generator.generate();
	}

	@Override
	public String sha256Hex(String plainToken) {
		return Sha256Hex.of(plainToken);
	}
}

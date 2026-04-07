package com.logistics.authentication.domain.exception;

import lombok.Getter;

@Getter
public class AuthenticationDomainException extends RuntimeException {

	private final String errorCode;

	public AuthenticationDomainException(String errorCode, String message) {
		super(message);
		this.errorCode = errorCode;
	}
}

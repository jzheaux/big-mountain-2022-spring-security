package com.example.api;

import java.util.function.Supplier;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

public final class IsNameAuthorizationManager<T> implements AuthorizationManager<T> {
	private final String name;

	private IsNameAuthorizationManager(String name) {
		this.name = name;
	}

	public static <T> IsNameAuthorizationManager<T> named(String name) {
		return new IsNameAuthorizationManager<>(name);
	}

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
		return new AuthorizationDecision(this.name.equals(authentication.get().getName()));
	}
}

package com.example.api;

import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.stereotype.Component;

@Component("authz")
public class FlightsAuthorization {
	public boolean all(SecurityExpressionOperations operations) {
		return "josh".equals(operations.getAuthentication().getName()) &&
				operations.hasAuthority("SCOPE_flights:read");
	}

	public boolean takeoff(SecurityExpressionOperations operations) {
		return "josh".equals(operations.getAuthentication().getName()) &&
				operations.hasAuthority("SCOPE_flights:write");
	}
}

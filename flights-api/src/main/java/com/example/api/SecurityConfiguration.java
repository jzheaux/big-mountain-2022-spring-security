package com.example.api;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import static com.example.api.IsNameAuthorizationManager.named;
import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority;
import static org.springframework.security.authorization.AuthorizationManagers.allOf;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration {
	@Bean
	SecurityFilterChain appFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authz) -> authz
				.requestMatchers("/flights/all").access(allOf(named("josh"), hasAuthority("SCOPE_flights:read")))
				.requestMatchers("/flights/*/take-off").access(allOf(named("josh"), hasAuthority("SCOPE_flights:read")))
				.requestMatchers("/flights").hasAuthority("SCOPE_flights:read")
				.anyRequest().hasAuthority("SCOPE_flights:write")
			)
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
		// @formatter:on
		return http.build();
	}
}

package com.example.api;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests((authz) -> authz
				.mvcMatchers("/flights/all").access("@authz.all(#root)")
				.mvcMatchers("/flights/*/take-off").access("@authz.takeoff(#root)")
				.mvcMatchers("/flights").hasAuthority("SCOPE_flights:read")
				.anyRequest().hasAuthority("SCOPE_flights:write")
			)
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
		// @formatter:on
	}
}

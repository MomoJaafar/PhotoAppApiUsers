package com.appsdeveloperblog.photoapp.api.users.security;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.appsdeveloperblog.photoapp.api.users.service.IUserService;

@Configuration
@EnableWebSecurity
public class WebSecurity {

	private Environment environment;
	
	@Autowired
	public WebSecurity(Environment environment, 
			IUserService userService,
			BCryptPasswordEncoder bCryptPasswordEncoder) {
		this.environment = environment;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
		this.userService = userService;
	}
	
	private IUserService userService;
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Bean
	protected SecurityFilterChain configure(HttpSecurity http) throws Exception {

		// Configure Authentication Manager Builder
		AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		authenticationManagerBuilder.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
		AuthenticationManager authenticationManager = authenticationManagerBuilder.build();
		
		// Create AuthenticationFilter
		AuthenticationFilter authenticationFilter = new AuthenticationFilter(userService, environment, authenticationManager);
		authenticationFilter.setFilterProcessesUrl(environment.getProperty("login.url.path"));
		
		http.csrf().disable();
		http.addFilterAfter(new Filter() {
			@Override
			public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
					throws IOException, ServletException {
				HttpServletRequest httpServletRequest = (HttpServletRequest) request;
				HttpServletResponse httpServletResponse = (HttpServletResponse) response;
				String remoteAddr = httpServletRequest.getRemoteAddr();

				if (remoteAddr.equals(environment.getProperty("gateway.ip"))) {
					chain.doFilter(request, response);
				} else {
					httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied!");
				}
			}
		}, BasicAuthenticationFilter.class)
		.authorizeHttpRequests()
		.regexMatchers(HttpMethod.POST, "/users").permitAll()
		.requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()
		.and()
		.addFilter(authenticationFilter)
		.authenticationManager(authenticationManager)
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.headers().frameOptions().disable();

		return http.build();
	}
}
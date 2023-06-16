/*
 * GovShell - Application dashboard for GovHub
 *
 * Copyright (c) 2021-2023 Link.it srl (http://www.link.it).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3, as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package it.govhub.govshell.proxy.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.govhub.govregistry.commons.security.AccessDeniedHandlerImpl;
import it.govhub.govregistry.commons.security.UnauthorizedAuthenticationEntryPoint;
import it.govhub.security.services.GovhubUserDetailService;



/**
 * Configurazione della sicurezza, per lo UserDetailService con govhub vedi:
 * 
 * https://stackoverflow.com/questions/36730903/add-custom-userdetailsservice-to-spring-security-oauth2-app
 * 
 */

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Value("${server.servlet.session.cookie.name:GOVHUB-JSESSIONID}")
	private String sessionCookieName;
	
	@Value("${govshell.auth.max-sessions:10}")
	private Integer maxSessions;
	
    @Value("${govhub.csp.policy:default-src 'self'}")
    String cspPolicy;
    
    @Value("${govshell.auth.type:form}")
    String authType;
    
    @Value("${govshell.auth.oauth.default-succes-url:/}")
    String defaultSuccessUrl;
    
    @Autowired
    LdapConfiguration ldapConfiguration;
	
	@Autowired
	LoginSuccessHandler loginSuccessHandler;
	
	@Autowired
	LoginFailureHandler loginFailureHandler;
	
	@Autowired
	ExpiredSessionHandler expiredSessionHandler;
	
	@Autowired
	GovhubUserDetailService userDetailsService;
	
	@Autowired
	LdapGovhubPrincipalMapper contextMapper;
	
	Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
	
	@Bean
	public AccessDeniedHandlerImpl accessDeniedHandler() {
		return new AccessDeniedHandlerImpl();
	}
	
	@Bean
	public OAuthGovhubUserService oauth2UserService() {
		return new OAuthGovhubUserService();
	}
	
	@Bean
	public OidcGovhubUserService oidcUserService() {
		return new OidcGovhubUserService();
	}
	
	  @Bean
	  public AuthenticationProvider daoAuthenticationProvider() {
	    var provider =  new DaoAuthenticationProvider();
	    provider.setPasswordEncoder(passwordEncoder());
	    provider.setUserDetailsService(this.userDetailsService);
	    return provider;
	  }
	  
	  
	@Bean
	@SuppressWarnings("deprecation")
	public static PasswordEncoder passwordEncoder() {
		String encodingId = "bcrypt";
		Map<String, PasswordEncoder> encoders = new HashMap<>();
		encoders.put(encodingId, new BCryptPasswordEncoder());
		encoders.put("ldap", new org.springframework.security.crypto.password.LdapShaPasswordEncoder());
		encoders.put("MD4", new org.springframework.security.crypto.password.Md4PasswordEncoder());
		encoders.put("MD5", new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("MD5"));
		encoders.put("noop", org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance());
		encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
		encoders.put("scrypt", new SCryptPasswordEncoder());
		encoders.put("SHA-1", new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-1"));
		encoders.put("SHA-256",
				new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-256"));
		encoders.put("sha256", new org.springframework.security.crypto.password.StandardPasswordEncoder());
		encoders.put("argon2", new Argon2PasswordEncoder());
		return new CustomDelegatingPasswordEncoder(encodingId, encoders);
	}
	
	@Bean
	public SecurityFilterChain securityFilterChainDev(HttpSecurity http, ObjectMapper jsonMapper) throws Exception {
		
		applyAuthRules(http)
		.csrf().disable();																												// Disabilita csrf perchè il cookie di sessione viene rilasciato con SameSite: strict
		
		if (authType.equals("oauth") ) {
			http.oauth2Login()
				.defaultSuccessUrl(defaultSuccessUrl, true)
				.userInfoEndpoint()
				.userService(oauth2UserService())
				.oidcUserService(oidcUserService());
		}

		http.formLogin()
				.loginProcessingUrl("/do-login")
				.successHandler(this.loginSuccessHandler)
				.failureHandler(this.loginFailureHandler)
				.and()
		.exceptionHandling()
		// Gestisci accessDenied in modo da restituire un problem ben formato TODO: Vedi se a govshell serve davero
		.accessDeniedHandler(this.accessDeniedHandler())																
		// Gestisci la mancata autenticazione con un problem ben formato
		.authenticationEntryPoint(new UnauthorizedAuthenticationEntryPoint(jsonMapper))	
		.and()
		.logout()
			.logoutUrl("/logout")
			.deleteCookies(this.sessionCookieName)
			.invalidateHttpSession(true)
			.logoutSuccessHandler(new DefaultLogoutSuccessHandler())
		.and()
		.headers()
			.xssProtection()
            .and()
         // Politica di CSP più restrittiva. https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
         // Anche le immagini dal gravatar
        .contentSecurityPolicy(this.cspPolicy);
		
	    http.sessionManagement()
	    	.maximumSessions(maxSessions)
	    	.expiredSessionStrategy(this.expiredSessionHandler);
	
		return http.build();
	}
	
	  @Autowired
	  public void configure(AuthenticationManagerBuilder auth) throws Exception {
		  
		  if (authType.equals("ldap") ) {
			  logger.info("Configuring Ldap Authentication..");
			  
			  auth
		      .ldapAuthentication()
		        .userDnPatterns(this.ldapConfiguration.getUserDnPatterns())
  	            .userSearchFilter(this.ldapConfiguration.getUserSearchFilter())
		        .userSearchBase(this.ldapConfiguration.getUserSearchBase())
		        .groupSearchBase(this.ldapConfiguration.getGroupSearchBase())
		        .groupSearchFilter(this.ldapConfiguration.getGroupSearchFilter())
		        .userDetailsContextMapper(contextMapper)
		        .contextSource()
		          .url(this.ldapConfiguration.getServerUrl())	
		          .port(this.ldapConfiguration.getServerPort())
		          .managerDn(this.ldapConfiguration.getManagerDn())
		    	  .managerPassword(this.ldapConfiguration.getManagerPassword());
		  } 
	  }
		  
	private HttpSecurity applyAuthRules(HttpSecurity http) throws Exception {
		http
		.authorizeRequests()
			.antMatchers("/", "/error").permitAll()
			.antMatchers("/actuator/**").permitAll()
			.anyRequest().authenticated();
		return http;
	}
	

	/**
	 * Pubblica gli eventi di sessione sul WebApplicationContext radice.
	 * Consente nel nostro caso di contare il numero di sessioni attive per utente e limitarlo di conseguenza.
	 * 
	 */
	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
	    return new HttpSessionEventPublisher();
	}
	
	
	public class DefaultLogoutSuccessHandler implements LogoutSuccessHandler {
	    @Override
	    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
	            response.setStatus(HttpServletResponse.SC_OK);
	    }
	}
	
}

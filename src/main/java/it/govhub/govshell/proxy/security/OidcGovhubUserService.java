package it.govhub.govshell.proxy.security;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import it.govhub.govregistry.commons.entity.UserEntity;
import it.govhub.govregistry.commons.messages.UserMessages;
import it.govhub.security.repository.SecurityUserRepository;

public class OidcGovhubUserService implements OAuth2UserService<OidcUserRequest, OidcUser>{
	
	@Autowired
	SecurityUserRepository userRepo;
	
	@Autowired
	UserMessages userMessages;
	
	@Value("${govshell.auth.oauth.principal-claim:}")
	String principalClaim;
	
	Logger log = LoggerFactory.getLogger(OidcGovhubUserService.class);
	
	OidcUserService oidcUserService = new OidcUserService();

	@Override
	public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
		
		log.debug("Loading Oidc user data...");
		
		OidcUser oidcUser = this.oidcUserService.loadUser(userRequest);
		
		log.debug("User claims:");
		for(var claim : oidcUser.getClaims().entrySet()) {
			log.debug("{}={}", claim.getKey(), claim.getValue());
		}
		
		String username;
		if (StringUtils.isEmpty(principalClaim)) {
			username = oidcUser.getName();
		} else {
			String claim = oidcUser.getAttribute(principalClaim);
			username = claim.strip();
		}
		
		log.debug("Retrieving the UserEntity with name: {}", username);
		
		UserEntity user = this.userRepo.findAndPreloadByPrincipal(username)
				.orElseThrow(() -> {
					log.error("Authenticated user with username [{}] not found.", username);
					return new UsernameNotFoundException(this.userMessages.principalNotFound(username)); 
				});
		
		return new OidcGovhubPrincipal(user, oidcUser);
	}

}

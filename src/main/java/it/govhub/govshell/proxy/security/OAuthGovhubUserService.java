package it.govhub.govshell.proxy.security;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

import it.govhub.govregistry.commons.entity.UserEntity;
import it.govhub.govregistry.commons.messages.UserMessages;
import it.govhub.security.repository.SecurityUserRepository;

public class OAuthGovhubUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
	
	DefaultOAuth2UserService authUserService = new DefaultOAuth2UserService();
	
	@Autowired
	SecurityUserRepository userRepo;
	
	@Autowired
	UserMessages userMessages;
	
	@Value("${govshell.auth.oauth.principal-claim:}")
	String principalClaim;
	
	Logger log = LoggerFactory.getLogger(OAuthGovhubUserService.class);

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		log.debug("Loading OAuth2 user data...");
		
		OAuth2User oauthUser = authUserService.loadUser(userRequest);
		
		log.debug("User attributes:");
		for(var attribute : oauthUser.getAttributes().entrySet()) {
			log.debug("{}={}", attribute.getKey(), attribute.getValue());
		}

		String username;
		if (StringUtils.isEmpty(principalClaim)) {
			username = oauthUser.getName();
		} else {
			String claim = oauthUser.getAttribute(principalClaim);
			if (claim == null) {
				log.error("Missing claim: {}", principalClaim);
				throw new UsernameNotFoundException(this.userMessages.principalNotFound(principalClaim)); 
			}
			username = claim.strip();
		}
		
		log.debug("Retrieving the UserEntity with name: {}", username);
		
		UserEntity user = this.userRepo.findAndPreloadByPrincipal(username)
				.orElseThrow(() -> {
					log.error("Authenticated user with username [{}] not found.", username);
					return new UsernameNotFoundException(this.userMessages.principalNotFound(username)); 
				});
		
		return new OAuthGovhubPrincipal(user, oauthUser);
	}

}

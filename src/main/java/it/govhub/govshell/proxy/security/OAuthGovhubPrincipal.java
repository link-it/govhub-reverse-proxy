package it.govhub.govshell.proxy.security;

import java.util.Map;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import it.govhub.govregistry.commons.entity.UserEntity;
import it.govhub.security.beans.GovhubPrincipal;

public class OAuthGovhubPrincipal extends GovhubPrincipal implements OAuth2User{
	
	private static final long serialVersionUID = 1L;
	private OAuth2User oauth2User;
	
	public OAuthGovhubPrincipal(UserEntity user, OAuth2User oauth2User) {
		super(user);
		this.oauth2User = oauth2User;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return oauth2User.getAttributes();
	}

	@Override
	public String getName() {
		return oauth2User.getName();
	}

}

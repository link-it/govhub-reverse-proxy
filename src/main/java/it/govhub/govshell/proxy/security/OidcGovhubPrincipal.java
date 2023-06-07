package it.govhub.govshell.proxy.security;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import it.govhub.govregistry.commons.entity.UserEntity;
import it.govhub.security.beans.GovhubPrincipal;

public class OidcGovhubPrincipal extends GovhubPrincipal implements OidcUser {
	
	private static final long serialVersionUID = 1L;
	
	OidcUser oidcUser;

	public OidcGovhubPrincipal(UserEntity user, OidcUser oidcUser) {
		super(user);
		this.oidcUser = oidcUser;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return oidcUser.getAttributes();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return oidcUser.getAuthorities();
	}

	@Override
	public String getName() {
		return oidcUser.getName();
	}

	@Override
	public Map<String, Object> getClaims() {
		return oidcUser.getClaims();
	}

	@Override
	public OidcUserInfo getUserInfo() {
		return oidcUser.getUserInfo();
	}

	@Override
	public OidcIdToken getIdToken() {
		return oidcUser.getIdToken();
	}

}

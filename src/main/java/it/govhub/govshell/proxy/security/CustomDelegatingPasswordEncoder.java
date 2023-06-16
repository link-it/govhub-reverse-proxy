package it.govhub.govshell.proxy.security;

import java.util.Map;

import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Un password encoder che restituisce false quando l'utente non ha una password assegnata,
 * in modo tale che non possa mai loggare.
 *
 */
public class CustomDelegatingPasswordEncoder extends DelegatingPasswordEncoder {

	public CustomDelegatingPasswordEncoder(String idForEncode, Map<String, PasswordEncoder> idToPasswordEncoder) {
		super(idForEncode, idToPasswordEncoder);
	}
	
	@Override
	public boolean matches(CharSequence rawPassword, String prefixEncodedPassword) {
		if (prefixEncodedPassword == null) {
			return false;
		}
		return super.matches(rawPassword, prefixEncodedPassword);
	}

	
}

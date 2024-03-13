/*
 * GovHub - Application suite for Public Administration
 *
 * Copyright (c) 2023-2024 Link.it srl (https://www.link.it).
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

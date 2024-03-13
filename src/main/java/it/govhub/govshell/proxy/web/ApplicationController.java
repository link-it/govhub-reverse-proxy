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
package it.govhub.govshell.proxy.web;

import java.net.URI;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.govhub.govregistry.commons.config.V1RestController;
import it.govhub.govregistry.commons.entity.ApplicationEntity;
import it.govhub.govregistry.commons.exception.InternalConfigurationException;
import it.govhub.govshell.proxy.beans.Application;
import it.govhub.govshell.proxy.beans.ApplicationList;
import it.govhub.govshell.proxy.repository.ApplicationRepository;

@V1RestController
public class ApplicationController implements ApplicationApi {
	
	@Autowired
	ApplicationRepository applicationRepo;
	
	@Autowired
	ObjectMapper objectMapper;

	@Override
	public ResponseEntity<ApplicationList> listApplications() {
		
		List<ApplicationEntity> applications = this.applicationRepo.findAll();
		
		ApplicationList ret = new ApplicationList();
		
		for (var app: applications) {
			Application item = new Application();
			
			try {
				if (app.getLogo() != null) {
					JsonNode logo  = this.objectMapper.readTree(app.getLogo());
					item.setLogo(logo);
				}
			} catch (JsonProcessingException e) {
				throw new InternalConfigurationException(e.getMessage());
			}
			
			item.setApplicationId(app.getApplicationId());
			item.setApplicationName(app.getName());
			item.setDeployedUri(URI.create(app.getDeployedUri()));
			if (app.getWebappUri() != null) {
				item.setWebappUri(URI.create(app.getWebappUri()));
			}
			ret.addItemsItem(item);
		}
		
		return ResponseEntity.ok(ret);
	}

}

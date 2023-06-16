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
package it.govhub.govshell.proxy.services;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.govhub.govregistry.commons.api.beans.Problem;
import it.govhub.govregistry.commons.entity.ApplicationEntity;
import it.govhub.govregistry.commons.entity.UserEntity;
import it.govhub.govregistry.commons.exception.ResourceNotFoundException;
import it.govhub.govregistry.commons.exception.handlers.RestResponseEntityExceptionHandler;
import it.govhub.govregistry.commons.messages.SystemMessages;
import it.govhub.govshell.proxy.beans.XForwardedHeaders;
import it.govhub.govshell.proxy.repository.ApplicationRepository;
import it.govhub.security.services.SecurityService;


@Service
public class ProxyService {
	
	final Logger logger = LoggerFactory.getLogger(ProxyService.class);
	
	// Alcuni header sono considerati "riservati" e non possono essere aggiunti  attraverso il Builder, li escludiamo a priori
	// per non gestire eccezioni. Questi header vengono determinati dai client, e dai proxy.
	final static TreeSet<String> reservedHeaders = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
	
	static {
		reservedHeaders.addAll(Set.of(HttpHeaders.HOST, HttpHeaders.CONNECTION));
	}

	@Value("${govshell.auth.header:Govhub-Consumer-Principal}")
	String headerAuthentication;

	@Value("${govshell.proxy.trace.header-name:Govshell-Trace-Id}")
	String traceHeaderName;

	@Value("${govshell.proxy.forwarded-prefix:}")
	String forwardedPrefix;
	
	@Value("${govshell.proxy.forwarded-for:}")
	String forwardedFor;
	
	@Value("${govshell.proxy.forwarded-host:}")
	String forwardedHost;
	
	@Value("${govshell.proxy.forwarded-proto:}")
	String forwardedProto;
	
	@Value("${govshell.proxy.forwarded-port:}")
	String forwardedPort;
	
	@Autowired
	ApplicationRepository appRepo;
	
	@Autowired
	ObjectMapper jsonMapper;
	
	TreeSet<String> responseBlackListHeaders;
	
	TreeSet<String> requestBlackListHeaders;
	
	HttpClient client;
	
	public ProxyService(
			@Value("${govshell.proxy.headers.response.blacklist:}")	List<String> responseBlackListHeaders,
			@Value("${govshell.proxy.headers.request.blacklist:}")	List<String> requestBlacklistHeaders,
			@Value("${govshell.proxy.connection-timeout:10}")	Integer connectionTimeout) {
		
		this.responseBlackListHeaders = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
		this.responseBlackListHeaders.addAll(responseBlackListHeaders);
		
		// Blacklist dello header di autenticazione
		this.requestBlackListHeaders = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
		this.requestBlackListHeaders.addAll(requestBlacklistHeaders);
		this.requestBlackListHeaders.add(this.headerAuthentication);
		
		// Aggiungiamo alla blacklist gli header che imposteremo manualmente, in modo da non creare duplicati.
		if (! StringUtils.isEmpty(this.forwardedPrefix)) {
			this.requestBlackListHeaders.add(XForwardedHeaders.Prefix);
		}
		if (! StringUtils.isEmpty(this.forwardedFor)) {
			this.requestBlackListHeaders.add(XForwardedHeaders.For);
		}
		if (! StringUtils.isEmpty(this.forwardedHost)) {
			this.requestBlackListHeaders.add(XForwardedHeaders.Host);
		}
		if (! StringUtils.isEmpty(this.forwardedPort)) {
			this.requestBlackListHeaders.add(XForwardedHeaders.Port);
		}
		if (! StringUtils.isEmpty(this.forwardedProto)) {
			this.requestBlackListHeaders.add(XForwardedHeaders.Proto);
		}
		
		this.client = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(connectionTimeout))
				.build();
	}
	

	public ResponseEntity<Resource> processProxyRequest(String applicationId, HttpServletRequest request)
			throws URISyntaxException, IOException, InterruptedException {

		String traceId = UUID.randomUUID().toString();
		logger.debug("Handling request with traceId [{}]", traceId);

		ThreadContext.put(this.traceHeaderName, traceId);

		// Se l'applicazione non c'è, restituiamo un 404 come fosse una pagina non esistente
		ApplicationEntity application = this.appRepo.findByApplicationId(applicationId)
				.orElseThrow(ResourceNotFoundException::new);

		URI applicationUri = new URI(application.getDeployedUri());
		String requestPath = (String) request.getAttribute(HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE);
		String prefix = "/" + applicationId;
		String resourcePath = requestPath.substring(prefix.length());
		URI destUri = UriComponentsBuilder.fromUri(applicationUri).path(resourcePath).query(request.getQueryString())
				.build(true).toUri();

		logger.debug("Proxying request: {}\nApplicationId: {}\nApplicationURI: {}\nSourceRequestPath: {}\nDestUri: {}", traceId, applicationId,
				applicationUri, requestPath, destUri);

		ServletInputStream inStream = request.getInputStream();

		Builder builder = HttpRequest.newBuilder()
				.uri(destUri)
				.method(request.getMethod(),
						HttpRequest.BodyPublishers.ofInputStream(() -> inStream));

		logger.debug("Request Headers: ");
		
		String actualForwardedPrefix = this.forwardedPrefix;
		Enumeration<String> headerNames = request.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			String name = headerNames.nextElement();
			String value = request.getHeader(name);
			
			logger.debug("{}: {}", name, value);

			if (!reservedHeaders.contains(name) && !reservedHeaders.contains(name)) {
				try {
					// Dopo dovrò impostare lo X-Forwarded-Prefix per riflettere il path dell'applicazione govhub chiamata. 
					// Qui me lo salvo nel caso non l'abbia già impostato con le properties.
					if (name.equalsIgnoreCase(XForwardedHeaders.Prefix)) {
							actualForwardedPrefix = value;
					}
					
					builder.header(name, value);
				} catch (IllegalArgumentException e) {
					logger.error("Header riservato {}", name);
				}
			}
		}

		builder.header(this.traceHeaderName, traceId);
		
		// Aggiungo header di autenticazione
		UserEntity principal = SecurityService.getPrincipal();
		builder.header(this.headerAuthentication, principal.getPrincipal());
		
		// Aggiungiamo eventuali headers di forwarding. Il prefix lo mettiamo sempre, perchè deve riflettere l'applicationId. 
		// Però se non lo stiamo sovrascrivendo, dobbiamo prendere il valore che già c'era, perciò "actualForwardedPrefix"
		builder.header("X-Forwarded-Prefix", actualForwardedPrefix + "/" + applicationId);
		
		if (! StringUtils.isEmpty(this.forwardedFor)) {
			builder.header(XForwardedHeaders.For, this.forwardedFor);
		}
		if (! StringUtils.isEmpty(this.forwardedHost)) {
			builder.header(XForwardedHeaders.Host, this.forwardedHost);
		}
		if (! StringUtils.isEmpty(this.forwardedPort)) {
			builder.header(XForwardedHeaders.Port, this.forwardedPort);
		}
		if (! StringUtils.isEmpty(this.forwardedProto)) {
			builder.header(XForwardedHeaders.Proto, this.forwardedProto);
		}

		HttpRequest newRequest = builder.build();
		HttpResponse<InputStream> response = null;
		try {
			response = this.client.send(newRequest, BodyHandlers.ofInputStream());
			logger.debug("Proxying request: {} - Got response from backend: {}", traceId, response.statusCode());
		} catch (ConnectException e) {
			
			logger.error("Connect Exception while contacting the backend: " + e.getLocalizedMessage());
			
			Problem p = RestResponseEntityExceptionHandler.buildProblem(HttpStatus.BAD_GATEWAY, "Can't connect to the backend service.");
			ByteArrayInputStream bs = new ByteArrayInputStream(jsonMapper.writeValueAsString(p).getBytes());
			InputStreamResource resourceStream = new InputStreamResource(bs);
			
			return new ResponseEntity<>(resourceStream, HttpStatus.BAD_GATEWAY);
		} catch (InterruptedException e) {
			
			logger.error("Request to the backend was aborted: " + e.getLocalizedMessage());
			
			Problem p = RestResponseEntityExceptionHandler.buildProblem(HttpStatus.BAD_GATEWAY, "Request to the backend service took to much.");
			ByteArrayInputStream bs = new ByteArrayInputStream(jsonMapper.writeValueAsString(p).getBytes());
			InputStreamResource resourceStream = new InputStreamResource(bs);
			
			return new ResponseEntity<>(resourceStream, HttpStatus.BAD_GATEWAY);
		}		
		if (response.statusCode() == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
			
			Problem p = RestResponseEntityExceptionHandler.buildProblem(HttpStatus.BAD_GATEWAY, SystemMessages.internalError());
			ByteArrayInputStream bs = new ByteArrayInputStream(jsonMapper.writeValueAsString(p).getBytes());
			InputStreamResource resourceStream = new InputStreamResource(bs);
			
			return new ResponseEntity<>(resourceStream, HttpStatus.BAD_GATEWAY);
		} else {
			
			HttpHeaders retHeaders = new HttpHeaders();
			response.headers().map().forEach((key, values) -> {
				if (!this.responseBlackListHeaders.contains(key)) {
					retHeaders.addAll(key, values);
				}
			});
			
			InputStreamResource resourceStream = new InputStreamResource(response.body());
			logger.debug("Proxying request: {} - Returning response to the client.", traceId);
			return new ResponseEntity<>(resourceStream, retHeaders, response.statusCode());
		}

	}
}
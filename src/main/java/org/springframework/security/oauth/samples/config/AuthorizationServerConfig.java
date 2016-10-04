/*
 * Copyright 2012-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth.samples.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

/**
 * @author Joe Grandja
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Value("${server.url}")
	private String serverUrl;

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		super.configure(security);
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		// @formatter:off
		clients.inMemory()
			.withClient("messaging-app-client")
				.authorizedGrantTypes("authorization_code", "refresh_token")
				.authorities("ROLE_CLIENT", "ROLE_MESSAGING_CLIENT")
				.scopes("message.read", "message.write")
				.secret("secret")
				.redirectUris(serverUrl + "/messaging")
				.and()
			.withClient("basic-client")
				.authorizedGrantTypes("client_credentials")
				.authorities("ROLE_CLIENT", "ROLE_MESSAGING_CLIENT")
				.scopes("message.read")
				.secret("secret");
		// @formatter:on
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		super.configure(endpoints);
	}
}
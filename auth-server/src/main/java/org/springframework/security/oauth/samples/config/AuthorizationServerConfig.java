/*
 * Copyright 2012-2018 the original author or authors.
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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.InMemoryApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Joe Grandja
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private ClientDetailsService clientDetailsService;

	@Autowired(required = false)
	private UserDetailsService userDetailsService;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		// @formatter:off
		clients.inMemory()
			.withClient("messaging-app-client")
				.authorizedGrantTypes("authorization_code", "refresh_token", "password")
				.authorities("ROLE_CLIENT", "ROLE_MESSAGING_CLIENT")
				.scopes("message.read", "message.write")
				.secret("secret")
				.redirectUris("http://localhost:8080/messaging", "http://localhost:8080/messaging/index");
		// @formatter:on
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
				.tokenStore(tokenStore())
				.userApprovalHandler(userApprovalHandler())
				.accessTokenConverter(accessTokenConverter())
				.authenticationManager(this.authenticationManager)
				.tokenServices(this.tokenServices());
	}

	@Bean
	public UserApprovalHandler userApprovalHandler() {
		ApprovalStoreUserApprovalHandler userApprovalHandler = new ApprovalStoreUserApprovalHandler();
		userApprovalHandler.setApprovalStore(approvalStore());
		userApprovalHandler.setClientDetailsService(this.clientDetailsService);
		userApprovalHandler.setRequestFactory(new DefaultOAuth2RequestFactory(this.clientDetailsService));
		return userApprovalHandler;
	}

	@Bean
	public AuthorizationServerTokenServices tokenServices() {
		final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
		defaultTokenServices.setClientDetailsService(this.clientDetailsService);
		defaultTokenServices.setSupportRefreshToken(true);
		defaultTokenServices.setTokenStore(tokenStore());
		defaultTokenServices.setTokenEnhancer(accessTokenConverter());
		defaultTokenServices.setAuthenticationManager(this.authenticationManager);

		return new AuthorizationServerTokenServices() {

			@Override
			public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
				UsernamePasswordAuthenticationToken userAuthentication =
						(UsernamePasswordAuthenticationToken) authentication.getUserAuthentication();
				User principal = (User) userAuthentication.getPrincipal();

				Map clientDetails = (Map) userAuthentication.getDetails();
				String clientId = (String) clientDetails.get("client_id");

				// Post-authentication callback
				// TODO Validate/authenticate user and/or client

				return defaultTokenServices.createAccessToken(authentication);
			}

			@Override
			public OAuth2AccessToken refreshAccessToken(String refreshToken, TokenRequest tokenRequest) throws AuthenticationException {
				return defaultTokenServices.refreshAccessToken(refreshToken, tokenRequest);
			}

			@Override
			public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
				return defaultTokenServices.getAccessToken(authentication);
			}
		};
	}

	@Bean
	public TokenStore tokenStore() {
		JwtTokenStore tokenStore = new JwtTokenStore(accessTokenConverter());
		tokenStore.setApprovalStore(approvalStore());
		return tokenStore;
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		final RsaSigner signer = new RsaSigner(KeyConfig.getSignerKey());

		JwtAccessTokenConverter converter = new JwtAccessTokenConverter() {
			private JsonParser objectMapper = JsonParserFactory.create();

			@Override
			protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
				String content;
				try {
					content = objectMapper.formatMap(getAccessTokenConverter().convertAccessToken(accessToken, authentication));
				} catch (Exception ex) {
					throw new IllegalStateException("Cannot convert access token to JSON", ex);
				}
				Map<String, String> headers = new HashMap<>();
				headers.put("kid", KeyConfig.VERIFIER_KEY_ID);
				String token = JwtHelper.encode(content, signer, headers).getEncoded();
				return token;
			}
		};
		converter.setSigner(signer);
		converter.setVerifier(new RsaVerifier(KeyConfig.getVerifierKey()));
		return converter;
	}

	@Bean
	public ApprovalStore approvalStore() {
		InMemoryApprovalStore store = new InMemoryApprovalStore();
		return store;
	}

	@Bean
	public JWKSet jwkSet() {
		RSAKey.Builder builder = new RSAKey.Builder(KeyConfig.getVerifierKey())
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.RS256)
				.keyID(KeyConfig.VERIFIER_KEY_ID);
		return new JWKSet(builder.build());
	}
}
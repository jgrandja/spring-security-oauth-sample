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
package org.springframework.security.oauth.samples.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author Joe Grandja
 */
@Controller
@RequestMapping("/messaging")
public class MessagingAppController {

	@Value("${messages.base-uri}")
	private String messagesBaseUri;

	@Autowired
	@Qualifier("messagingAppRestTemplate")
	private OAuth2RestTemplate messagingAppRestTemplate;

	@RequestMapping(method = RequestMethod.GET)
	public String root() {
		return "redirect:/messaging/index";
	}

	@RequestMapping("/index")
	@ResponseBody
	public String[] index() {
		String[] messages = messagingAppRestTemplate.getForObject(messagesBaseUri, String[].class);

		return messages;
	}

}
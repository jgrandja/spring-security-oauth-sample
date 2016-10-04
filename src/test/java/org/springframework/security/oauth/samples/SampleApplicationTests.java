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
package org.springframework.security.oauth.samples;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 *
 * @author Joe Grandja
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = SampleApplication.class)
@AutoConfigureMockMvc
public class SampleApplicationTests {

	@Autowired
	private WebApplicationContext context;

	@Autowired
	MockMvc mockMvc;

	@Before
	public void setup() {
	}

	@Test
	public void accessUnprotected() throws Exception {
		this.mockMvc.perform(get("/index"))
				.andExpect(status().isOk());
	}

	@Test
	public void accessProtectedRedirectsToLogin() throws Exception {
		MvcResult mvcResult = this.mockMvc.perform(get("/user/index"))
				.andExpect(status().is3xxRedirection())
				.andReturn();

		assertThat(mvcResult.getResponse().getRedirectedUrl()).endsWith("/login");
	}

	@Test
	public void loginUser() throws Exception {
		this.mockMvc.perform(formLogin().user("user").password("password"))
				.andExpect(authenticated());
	}

	@Test
	public void loginInvalidUser() throws Exception {
		this.mockMvc.perform(formLogin().user("invalid").password("invalid"))
				.andExpect(unauthenticated())
				.andExpect(status().is3xxRedirection());
	}

	@Test
	public void loginUserAccessProtected() throws Exception {
		MvcResult mvcResult = this.mockMvc.perform(formLogin().user("user").password("password"))
				.andExpect(authenticated())
				.andReturn();

		MockHttpSession httpSession = MockHttpSession.class.cast(mvcResult.getRequest().getSession(false));

		this.mockMvc.perform(get("/user/index")
				.session(httpSession))
				.andExpect(status().isOk());
	}

	@Test
	public void loginUserValidateLogout() throws Exception {
		MvcResult mvcResult = this.mockMvc.perform(formLogin().user("user").password("password"))
				.andExpect(authenticated())
				.andReturn();

		MockHttpSession httpSession = MockHttpSession.class.cast(mvcResult.getRequest().getSession(false));

		this.mockMvc.perform(post("/logout").with(csrf())
				.session(httpSession))
				.andExpect(unauthenticated());

		this.mockMvc.perform(get("/user/index")
				.session(httpSession))
				.andExpect(unauthenticated())
				.andExpect(status().is3xxRedirection());
	}
}

/*
 * Copyright 2013-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.newland.resilience4j;

import java.util.Map;
import java.util.function.Supplier;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * @author Ryan Baxter
 */
@Service
public class HttpBinService {

	private RestTemplate rest;

	public HttpBinService(RestTemplate rest) {
		this.rest = rest;
	}

	public Map get() {
		return rest.getForObject("https://httpbin.org/get", Map.class);

	}

	public Map delay(int seconds) {
		return rest.getForObject("https://httpbin.org/delay/" + seconds, Map.class);
	}

	public Supplier<Map> delaySuppplier(int seconds) {
		return () -> this.delay(seconds);
	}
}

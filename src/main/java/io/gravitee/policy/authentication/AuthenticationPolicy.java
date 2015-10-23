/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.authentication;

import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.policy.PolicyChain;
import io.gravitee.gateway.api.policy.PolicyResult;
import io.gravitee.gateway.api.policy.annotations.OnRequest;
import io.gravitee.policy.authentication.manager.AuthenticationManager;
import io.gravitee.policy.authentication.manager.BasicAuthenticationManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author David BRASSELY (brasseld at gmail.com)
 */
@SuppressWarnings("unused")
public class AuthenticationPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationPolicy.class);

    private final AuthenticationManager authenticationManager = new BasicAuthenticationManager();

    @OnRequest
    public void onRequest(Request request, Response response, PolicyChain policyChain) {
        PolicyResult policyResult = authenticationManager.authenticate(request, response);
        if (policyResult.isFailure()) {
            policyChain.failWith(policyResult);
        }

        policyChain.doNext(request, response);
    }
}

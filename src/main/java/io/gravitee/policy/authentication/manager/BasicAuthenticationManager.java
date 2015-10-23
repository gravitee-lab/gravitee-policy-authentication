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
package io.gravitee.policy.authentication.manager;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.policy.PolicyResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author David BRASSELY (brasseld at gmail.com)
 */
public class BasicAuthenticationManager implements AuthenticationManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(BasicAuthenticationManager.class);

    private static final String BASIC_AUTHORIZATION_SEPARATOR = ":";

    @Override
    public PolicyResult authenticate(Request request, Response response) {
        final String authorizationHeader = request.headers().getFirst(HttpHeaders.AUTHORIZATION);

        LOGGER.debug("Looking for {} header from request {}", HttpHeaders.AUTHORIZATION, request.id());

        if (authorizationHeader == null || authorizationHeader.isEmpty()) {
            LOGGER.debug("No {} header value for request {}. Returning 401 status code.",
                    HttpHeaders.AUTHORIZATION, request.id());
            response.headers().set(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"gravitee-realm\"");
            // The authorization header is required
            return new PolicyResult() {
                @Override
                public boolean isFailure() {
                    return true;
                }

                @Override
                public int httpStatusCode() {
                    return HttpStatusCode.UNAUTHORIZED_401;
                }

                @Override
                public String message() {
                    return "An HTTP header value must be specified for " + HttpHeaders.AUTHORIZATION;
                }
            };
        } else {
            String username = null;
            String password = null;

            if (authorizationHeader.length() > "Basic ".length()) {
                String usernamePassword = new String(javax.xml.bind.DatatypeConverter.parseBase64Binary(
                        authorizationHeader.substring("Basic ".length())));
                if (usernamePassword.contains(BASIC_AUTHORIZATION_SEPARATOR)) {
                    username = usernamePassword.substring(0, usernamePassword.indexOf(BASIC_AUTHORIZATION_SEPARATOR));
                    if (usernamePassword.indexOf(BASIC_AUTHORIZATION_SEPARATOR) + 1 < usernamePassword.length()) {
                        password = usernamePassword.substring(usernamePassword.indexOf(BASIC_AUTHORIZATION_SEPARATOR) + 1);
                    }
                }
            }

            if (username == null || password == null) {
                return new PolicyResult() {
                    @Override
                    public boolean isFailure() {
                        return true;
                    }

                    @Override
                    public int httpStatusCode() {
                        return HttpStatusCode.UNAUTHORIZED_401;
                    }

                    @Override
                    public String message() {
                        return "A correct HTTP header value must be specified for " + HttpHeaders.AUTHORIZATION;
                    }
                };
            } else {

            }
        }

        return new PolicyResult() {
            @Override
            public boolean isFailure() {
                return false;
            }

            @Override
            public int httpStatusCode() {
                return 0;
            }

            @Override
            public String message() {
                return null;
            }
        };
    }
}

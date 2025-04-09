/*
 * Copyright (C) 2025 Dremio Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.dremio.iceberg.authmgr.oauth2.flow;

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthenticator;
import org.apache.iceberg.rest.RESTClient;

public class FlowFactory {

  public static Flow forInitialTokenFetch(
      OAuth2AgentSpec config,
      RESTClient restClient,
      EndpointResolver endpointResolver,
      ClientAuthenticator clientAuthenticator) {
    switch (config.getBasicConfig().getGrantType()) {
      case CLIENT_CREDENTIALS:
        return new ClientCredentialsFlow(config, restClient, endpointResolver, clientAuthenticator);
      case PASSWORD:
        return new PasswordFlow(config, restClient, endpointResolver, clientAuthenticator);
      case AUTHORIZATION_CODE:
        return new AuthorizationCodeFlow(config, restClient, endpointResolver, clientAuthenticator);
      case DEVICE_CODE:
        return new DeviceCodeFlow(config, restClient, endpointResolver, clientAuthenticator);
      case TOKEN_EXCHANGE:
        return new TokenExchangeFlow(config, restClient, endpointResolver, clientAuthenticator);
      default:
        throw new IllegalArgumentException(
            "Unknown or invalid grant type for initial token fetch: "
                + config.getBasicConfig().getGrantType());
    }
  }

  public static Flow forTokenRefresh(
      OAuth2AgentSpec config,
      RESTClient restClient,
      EndpointResolver endpointResolver,
      ClientAuthenticator clientAuthenticator) {
    switch (config.getBasicConfig().getDialect()) {
      case STANDARD:
        return new RefreshTokenFlow(config, restClient, endpointResolver, clientAuthenticator);
      case ICEBERG_REST:
        return new IcebergRefreshTokenFlow(
            config, restClient, endpointResolver, clientAuthenticator);
      default:
        throw new IllegalArgumentException(
            "Unknown or invalid dialect: " + config.getBasicConfig().getDialect());
    }
  }

  public static Flow forImpersonation(
      OAuth2AgentSpec config,
      RESTClient restClient,
      EndpointResolver endpointResolver,
      ClientAuthenticator clientAuthenticator) {
    return new ImpersonatingTokenExchangeFlow(
        config, restClient, endpointResolver, clientAuthenticator);
  }
}

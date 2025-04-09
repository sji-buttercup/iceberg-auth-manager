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

import com.dremio.iceberg.authmgr.oauth2.token.Tokens;

/**
 * A specialized {@link TokenExchangeFlow} that is performed after the initial token fetch flow, in
 * order to obtain a more fine-grained token through impersonation (or delegation).
 */
class ImpersonatingTokenExchangeFlow extends TokenExchangeFlow {

  ImpersonatingTokenExchangeFlow(FlowContext context) {
    super(context);
  }

  @Override
  public Tokens fetchNewTokens(Tokens currentTokens) {
    Tokens newTokens = super.fetchNewTokens(currentTokens);
    // return the new, impersonated access token, but keep the current refresh token
    // so that the original access token can be refreshed, then impersonated again.
    return Tokens.of(newTokens.getAccessToken(), currentTokens.getRefreshToken());
  }
}

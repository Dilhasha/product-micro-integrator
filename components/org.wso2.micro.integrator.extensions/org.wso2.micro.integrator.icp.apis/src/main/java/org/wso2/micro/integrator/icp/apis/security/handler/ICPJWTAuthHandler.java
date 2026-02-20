/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.micro.integrator.icp.apis.security.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.wso2.config.mapper.ConfigParser;
import org.wso2.micro.core.util.CarbonException;
import org.wso2.micro.integrator.initializer.dashboard.Constants;
import static org.wso2.micro.integrator.management.apis.Constants.ICP_AUTHENTICATED_PROPERTY;
import org.wso2.micro.integrator.initializer.dashboard.HMACJWTTokenGenerator;
import org.wso2.micro.integrator.management.apis.ManagementApiUndefinedException;
import org.wso2.micro.integrator.management.apis.security.handler.AuthenticationHandlerAdapter;

import java.io.IOException;
import javax.xml.stream.XMLStreamException;

/**
 * Security handler for the Management API that validates HMAC-based JWT tokens issued by ICP.
 * Enabled when {@code icp_config.enabled = true} in deployment.toml.
 * Uses the shared {@code icp_config.jwt_hmac_secret} to verify incoming Bearer tokens,
 * allowing ICP to authenticate against MI's Management API without basic auth credentials.
 */
public class ICPJWTAuthHandler extends AuthenticationHandlerAdapter {

    private static final Log LOG = LogFactory.getLog(ICPJWTAuthHandler.class);

    private String name;
    private String jwtHmacSecret;

    /**
     * Constructor required by ConfigurationLoader (instantiated via reflection).
     *
     * @param context the API context path
     */
    public ICPJWTAuthHandler(String context) throws CarbonException, XMLStreamException, IOException,
            ManagementApiUndefinedException {
        super(context);
        LOG.info("ICPJWTAuthHandler initialized for context: " + context);
    }

    @Override
    public Boolean invoke(MessageContext messageContext) {
        return super.invoke(messageContext);
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    protected Boolean authenticate(MessageContext messageContext, String authHeaderToken) {
        if (jwtHmacSecret == null || jwtHmacSecret.trim().isEmpty()) {
            Object secretObj = ConfigParser.getParsedConfigs().get(Constants.ICP_JWT_HMAC_SECRET);
            if (secretObj != null && !secretObj.toString().trim().isEmpty()) {
                jwtHmacSecret = secretObj.toString().trim();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("JWT HMAC secret loaded from deployment.toml for ICPJWTAuthHandler");
                }
            }
        }
        if (jwtHmacSecret == null || jwtHmacSecret.trim().isEmpty()) {
            LOG.error("JWT HMAC secret is not configured for ICPJWTAuthHandler. "
                    + "Set icp_config.jwt_hmac_secret in deployment.toml");
            return false;
        }
        try {
            HMACJWTTokenGenerator validator = new HMACJWTTokenGenerator(jwtHmacSecret);
            boolean valid = validator.validateToken(authHeaderToken);
            if (valid) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("HMAC JWT token validated successfully for ICP Management API request");
                }
                messageContext.setProperty(ICP_AUTHENTICATED_PROPERTY, true);
                return true;
            }
        } catch (IllegalArgumentException e) {
            LOG.error("Invalid HMAC secret configured for ICPJWTAuthHandler", e);
        }
        // Not an ICP HMAC token — pass through to let JWTTokenSecurityHandler authenticate
        if (LOG.isDebugEnabled()) {
            LOG.debug("Token is not a valid ICP HMAC JWT, passing through to next authentication handler");
        }
        return true;
    }

}

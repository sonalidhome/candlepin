/**
 * Copyright (c) 2009 - 2012 Red Hat, Inc.
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package org.candlepin.auth;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;

import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.OAuthRequestAuthenticator;
import org.keycloak.adapters.AdapterUtils;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.QueryParamterTokenRequestAuthenticator;
import org.keycloak.adapters.BearerTokenRequestAuthenticator;
import org.keycloak.adapters.BasicAuthRequestAuthenticator;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.spi.KeycloakAccount;

import java.security.Principal;
import java.util.Set;

/**
 * KeycloakRequestAuthenticator is a customized RequestAuthenticator for Keycloak Integration
 */
public class KeycloakRequestAuthenticator extends RequestAuthenticator {
    private HttpRequest httpRequest;
    RefreshableKeycloakSecurityContext securityContext = null;
    public KeycloakRequestAuthenticator(HttpFacade facade, KeycloakDeployment deployment,
        HttpRequest httpRequest) {
        super(facade, deployment);
        this.httpRequest = httpRequest;
    }

    @Override
    protected OAuthRequestAuthenticator createOAuthAuthenticator() {
        return new OAuthRequestAuthenticator(this, facade, deployment, sslRedirectPort, tokenStore);

    }

    @Override
    protected void completeOAuthAuthentication(
        KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal) {

    }

    @Override
    protected void completeBearerAuthentication(
        KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal, String method) {
        securityContext = principal.getKeycloakSecurityContext();

        final Set<String> roles = AdapterUtils.getRolesFromSecurityContext(securityContext);

        httpRequest.setAttribute(KeycloakSecurityContext.class.getName(), securityContext);
        OidcKeycloakAccount account = new OidcKeycloakAccount() {

            @Override
            public Principal getPrincipal() {
                return principal;
            }

            @Override
            public Set<String> getRoles() {
                return roles;
            }

            @Override
            public KeycloakSecurityContext getKeycloakSecurityContext() {
                return securityContext;
            }

        };
        // need this here to obtain UserPrincipal
        httpRequest.setAttribute(KeycloakAccount.class.getName(), account);

    }

    @Override
    protected String changeHttpSessionId(boolean create) {
        return null;
    }

    public AuthOutcome authenticate() {
        if (log.isTraceEnabled()) {
            log.trace("--> authenticate()");
        }

        BearerTokenRequestAuthenticator bearer = createBearerTokenAuthenticator();
        if (log.isTraceEnabled()) {
            log.trace("try bearer");
        }

        AuthOutcome outcome = bearer.authenticate(facade);
        if (outcome == AuthOutcome.FAILED) {
            challenge = bearer.getChallenge();
            log.debug("Bearer FAILED");
            return AuthOutcome.FAILED;
        }
        else if (outcome == AuthOutcome.AUTHENTICATED) {
            if (verifySSL()) {
                return AuthOutcome.FAILED;
            }
            completeAuthentication(bearer, "KEYCLOAK");
            log.debug("Bearer AUTHENTICATED");
            return AuthOutcome.AUTHENTICATED;
        }

        QueryParamterTokenRequestAuthenticator queryParamAuth =
            createQueryParamterTokenRequestAuthenticator();
        if (log.isTraceEnabled()) {
            log.trace("try query paramter auth");
        }

        outcome = queryParamAuth.authenticate(facade);
        if (outcome == AuthOutcome.FAILED) {
            challenge = queryParamAuth.getChallenge();
            log.debug("QueryParamAuth auth FAILED");
            return AuthOutcome.FAILED;
        }
        else if (outcome == AuthOutcome.AUTHENTICATED) {
            if (verifySSL()) {
                return AuthOutcome.FAILED;
            }
            log.debug("QueryParamAuth AUTHENTICATED");
            completeAuthentication(queryParamAuth, "KEYCLOAK");
            return AuthOutcome.AUTHENTICATED;
        }

        if (deployment.isEnableBasicAuth()) {
            BasicAuthRequestAuthenticator basicAuth = createBasicAuthAuthenticator();
            if (log.isTraceEnabled()) {
                log.trace("try basic auth");
            }

            outcome = basicAuth.authenticate(facade);
            if (outcome == AuthOutcome.FAILED) {
                challenge = basicAuth.getChallenge();
                log.debug("BasicAuth FAILED");
                return AuthOutcome.FAILED;
            }
            else if (outcome == AuthOutcome.AUTHENTICATED) {
                if (verifySSL()) {
                    return AuthOutcome.FAILED;
                }
                log.debug("BasicAuth AUTHENTICATED");
                completeAuthentication(basicAuth, "BASIC");
                return AuthOutcome.AUTHENTICATED;
            }
        }

        if (deployment.isBearerOnly()) {
            challenge = bearer.getChallenge();
            log.debug("NOT_ATTEMPTED: bearer only");
            return AuthOutcome.NOT_ATTEMPTED;
        }

        if (isAutodetectedBearerOnly(facade.getRequest())) {
            challenge = bearer.getChallenge();
            log.debug("NOT_ATTEMPTED: Treating as bearer only");
            return AuthOutcome.NOT_ATTEMPTED;
        }

        if (log.isTraceEnabled()) {
            log.trace("try oauth");
        }

        OAuthRequestAuthenticator oauth = createOAuthAuthenticator();
        outcome = oauth.authenticate();
        if (outcome == AuthOutcome.FAILED) {
            challenge = oauth.getChallenge();
            return AuthOutcome.FAILED;
        }
        else if (outcome == AuthOutcome.NOT_ATTEMPTED) {
            challenge = oauth.getChallenge();
            return AuthOutcome.NOT_ATTEMPTED;

        }

        if (verifySSL()) {
            return AuthOutcome.FAILED;
        }

        completeAuthentication(oauth);

        // redirect to strip out access code and state query parameters
        facade.getResponse().setHeader("Location", oauth.getStrippedOauthParametersRequestUri());
        facade.getResponse().setStatus(302);
        facade.getResponse().end();

        log.debug("AUTHENTICATED");
        return AuthOutcome.AUTHENTICATED;
    }

}

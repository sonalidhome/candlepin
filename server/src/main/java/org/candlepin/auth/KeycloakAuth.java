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


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.candlepin.config.ConfigProperties;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.TokenVerifier;
import org.apache.commons.codec.binary.Base64;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.ws.rs.core.Context;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Set;

import org.candlepin.auth.permissions.PermissionFactory;
import org.candlepin.common.exceptions.CandlepinException;
import org.candlepin.common.exceptions.ServiceUnavailableException;
import org.candlepin.common.resteasy.auth.AuthUtil;
import org.keycloak.KeycloakSecurityContext;
import org.candlepin.service.UserServiceAdapter;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AdapterUtils;
import org.keycloak.adapters.OAuthRequestAuthenticator;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.ServerRequest;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;

import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xnap.commons.i18n.I18n;
import javax.inject.Provider;

/**
 * KeycloakAuth
 */
public class KeycloakAuth extends UserAuth implements AuthProvider {

    @Context private ServletRequest servletRequest;
    @Context private ServletResponse servletResponse;

    private static Logger log = LoggerFactory.getLogger(KeycloakAuth.class);
    protected AdapterDeploymentContext deploymentContext;
    private AccessTokenResponse response = null;
    private KeycloakDeployment kd;
    private String filepath = null;
    private RefreshableKeycloakSecurityContext securityContext = null;

    /**
     * Enum for Different types of Tokens
     */
    public enum Token {
        BEARER,
        REFRESH
    }

    @Inject
    public KeycloakAuth(UserServiceAdapter userServiceAdapter, Provider<I18n> i18nProvider,
        PermissionFactory permissionFactory) {
        super(userServiceAdapter, i18nProvider, permissionFactory);
        createKeycloakDeploymentFrom();
    }

    private void createKeycloakDeploymentFrom() {

        try {
            InputStream is = loadKeycloakConfigFile();
            kd = KeycloakDeploymentBuilder.build(is);
            deploymentContext = new AdapterDeploymentContext(kd);
        }
        catch (FileNotFoundException e) {
            log.error("{} :File not found", filepath);
        }
    }

    private InputStream loadKeycloakConfigFile() throws FileNotFoundException {
        filepath = ConfigProperties.KEYCLOAK_FILEPATH;
        return new FileInputStream(filepath);
    }


    @Override
    public Principal getPrincipal(HttpRequest httpRequest) {
        try {
            String auth = AuthUtil.getHeader(httpRequest, "Authorization");

            if (!auth.isEmpty()) {

                String[] authArray = auth.split(" ");
                if (authArray[0].equals("Basic")) {
                    return null;
                }
                else {
                    try {
                        Base64 base64Url = new Base64(true);
                        String[] splitstring = authArray[1].split("\\.");
                        String base64EncodedBody = splitstring[1];
                        String body = new String(base64Url.decode(base64EncodedBody));
                        ObjectMapper objectMapper = new ObjectMapper();
                        JsonNode rootNode = objectMapper.readTree(body);
                        String tokenType = rootNode.get("typ").asText();
                        Token token = Token.valueOf(tokenType.toUpperCase());
                        switch(token) {
                            case BEARER:
                                handleBearerToken(httpRequest);
                                break;
                            case REFRESH:
                                handleRefreshToken(httpRequest, auth);
                                break;
                            default:
                                break;
                        }
                    }
                    catch (UnsupportedEncodingException e) {
                        throw new UnsupportedEncodingException(i18nProvider.get().tr("Decoding Failed"));
                    }
                }
                KeycloakSecurityContext keycloakSecurityContext = (KeycloakSecurityContext)
                    httpRequest.getAttribute(KeycloakSecurityContext.class.getName());
                if (keycloakSecurityContext != null) {
                    String userName = keycloakSecurityContext.getToken().getPreferredUsername();
                    Principal principal = createPrincipal(userName);
                    return principal;
                }
            }
            else {
                // if auth header is empty
                return null;
            }
        }
        catch (CandlepinException e) {
            throw e;
        }
        catch (Exception e) {
            throw new ServiceUnavailableException(i18nProvider.get().tr("Keycloak Authentication failed"));
        }
        return null;
    }


    private void handleBearerToken(HttpRequest httpRequest) {

        KeycloakOIDCFacade keycloakOIDCFacade = new KeycloakOIDCFacade(httpRequest);
        RequestAuthenticator requestAuthenticator = new RequestAuthenticator(keycloakOIDCFacade, kd) {
            @Override
            protected OAuthRequestAuthenticator createOAuthAuthenticator() {
                return null;
            }

            @Override
            protected void completeOAuthAuthentication(KeycloakPrincipal<RefreshableKeycloakSecurityContext>
                principal) {
                 //intentionally left empty
            }

            @Override
            protected void completeBearerAuthentication(
                KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal, String method) {
                securityContext = principal.getKeycloakSecurityContext();

                final Set<String> roles = AdapterUtils.getRolesFromSecurityContext(securityContext);

                httpRequest.setAttribute(KeycloakSecurityContext.class.getName(), securityContext);
                OidcKeycloakAccount account = new OidcKeycloakAccount() {

                    @Override
                    public java.security.Principal getPrincipal() {
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
        };
        requestAuthenticator.authenticate();

    }

    private void handleRefreshToken(HttpRequest httpRequest, String auth) throws IOException,
        ServerRequest.HttpFailure, VerificationException {

        String[] arrAut = auth.split(" ");
        response = ServerRequest.invokeRefresh(kd, arrAut[1]);
        String tokenString = response.getToken();
        AccessToken token = TokenVerifier.create(response.getToken(), AccessToken.class).getToken();
        RefreshableKeycloakSecurityContext refreshableKeycloakSecurityContext = new
            RefreshableKeycloakSecurityContext(kd, null, tokenString, token, null, null, arrAut[1]);
        httpRequest.setAttribute(KeycloakSecurityContext.class.getName(), refreshableKeycloakSecurityContext);

    }
}

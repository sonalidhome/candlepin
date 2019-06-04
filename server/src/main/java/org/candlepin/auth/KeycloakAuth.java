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
import org.json.JSONObject;
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
import org.candlepin.auth.permissions.PermissionFactory;
import org.candlepin.common.exceptions.CandlepinException;
import org.candlepin.common.exceptions.ServiceUnavailableException;
import org.candlepin.common.resteasy.auth.AuthUtil;

import org.keycloak.KeycloakSecurityContext;
import org.candlepin.service.UserServiceAdapter;
import org.keycloak.adapters.AdapterDeploymentContext;

import org.keycloak.adapters.ServerRequest;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;

import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.xnap.commons.i18n.I18n;

import javax.inject.Provider;
/**
 * KeycloakAuth
 */

public class KeycloakAuth extends UserAuth implements AuthProvider {

    @Context private ServletRequest servletRequest;
    @Context private ServletResponse servletResponse;

    protected AdapterDeploymentContext deploymentContext;

    private AccessTokenResponse response = null;

    private KeycloakDeployment kd;

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
        catch (Exception e) {

        }

    }

    private InputStream loadKeycloakConfigFile() throws FileNotFoundException {
        String filepath = "/etc/candlepin/keycloak.json";
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
                    Base64 base64Url = new Base64(true);
                    String[] splitstring = authArray[1].split("\\.");
                    String base64EncodedBody = splitstring[1];
                    String body = new String(base64Url.decode(base64EncodedBody));
                    JSONObject obj = new JSONObject(body);
                    String tokenType = obj.getString("typ");

                    if (tokenType.equals("Refresh")) {
                        //Offline Token authentication
                        handleRefreshToken(httpRequest, auth);
                    }
                    else if (tokenType.equals("Bearer")) {
                        //Bearer only authentication
                        handleBearerToken(httpRequest);
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
        KeycloakRequestAuthenticator requestAuthenticator =
            new KeycloakRequestAuthenticator(keycloakOIDCFacade, kd, httpRequest);
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

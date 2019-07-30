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
package org.candlepin.resteasy.filter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.candlepin.auth.CandlepinKeycloakRequestAuthenticator;
import org.candlepin.auth.KeycloakAdapterConfiguration;
import org.candlepin.auth.KeycloakOIDCFacade;
import org.candlepin.auth.NoAuthPrincipal;
import org.candlepin.auth.Principal;
import org.candlepin.auth.UserPrincipal;
import org.candlepin.auth.permissions.PermissionFactory;
import org.candlepin.common.auth.SecurityHole;
import org.candlepin.common.exceptions.BadRequestException;
import org.candlepin.common.exceptions.NotAuthorizedException;
import org.candlepin.config.ConfigProperties;
import org.candlepin.model.ConsumerCurator;
import org.candlepin.model.DeletedConsumerCurator;
import org.candlepin.model.User;
import org.candlepin.service.UserServiceAdapter;
import org.candlepin.test.DatabaseTestFixture;

import com.google.inject.AbstractModule;
import com.google.inject.Injector;
import com.google.inject.Module;

import org.jboss.resteasy.core.ResourceMethodInvoker;
import org.jboss.resteasy.core.interception.PostMatchContainerRequestContext;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.TokenVerifier;
import org.keycloak.adapters.BearerTokenRequestAuthenticator;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import java.lang.reflect.Method;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ResourceInfo;

/**
 * AuthInterceptorTest
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class AuthenticationFilterTest extends DatabaseTestFixture {
    @Inject private DeletedConsumerCurator deletedConsumerCurator;
    @Inject private Injector injector;

    @Mock private HttpServletRequest mockHttpServletRequest;
    @Mock private ContainerRequestContext mockRequestContext;
    @Mock private CandlepinSecurityContext mockSecurityContext;
    @Mock private ResourceInfo mockInfo;
    @Mock private UserServiceAdapter usa;
    @Mock private KeycloakAdapterConfiguration keycloakAdapterConfiguration;
    @Mock private AdapterConfig adapterConfig;
    @Mock private BearerTokenRequestAuthenticator bearerTokenRequestAuthenticator;
    @Mock private KeycloakDeployment keycloakDeployment;

    @SuppressWarnings("LineLength")
    private static final String TESTTOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJiNzJiZDlkNi00MDczLTQ2NWUtYTY5YS05NDA2MGZiMjY4Y2QiLCJleHAiOjE1NjQ1MjA3MjIsIm5iZiI6MCwiaWF0IjoxNTY0NTE2MjAzLCJpc3MiOiJodHRwczovL3Nzby5kZXYxL3JlZGhhdC1leHRlcm5hbCIsImF1ZCI6ImNhbmRsZXBpbi10ZXN0Iiwic3ViIjoiZjplNDRhYTg0ZS0zYjc2LTQwMjgtOTUzNS1hNTQwMDM5MWQwMGY6YmNvdXJ0QHJlZGhhdC5jb20iLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJjYW5kbGVwaW4tdGVzdCIsIm5vbmNlIjoiNWNjZGRhZTUtMWJhMS00MTM2LWEzODgtNTc2ZDNjMGQzNWY4IiwiYXV0aF90aW1lIjoxNTY0NDkzODU3LCJzZXNzaW9uX3N0YXRlIjoiMjk1MTA5ZTYtYjU0MC00MmJjLTlkMGQtYzgzZjE2YTY2MzJiIiwiYWNyIjoiMCIsImFsbG93ZWQtb3JpZ2lucyI6WyIqIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJhdXRoZW50aWNhdGVkIiwiY2FuZGxlcGluX3N5c3RlbV9hY2Nlc3Nfdmlld19lZGl0X3BlcnNvbmFsIiwicmVkaGF0OmVtcGxveWVlcyIsInBvcnRhbF9tYW5hZ2Vfc3Vic2NyaXB0aW9ucyIsInVtYV9hdXRob3JpemF0aW9uIiwicG9ydGFsX21hbmFnZV9jYXNlcyIsImNsb3VkX2FjY2Vzc18xIiwicG9ydGFsX3N5c3RlbV9tYW5hZ2VtZW50IiwicG9ydGFsX2Rvd25sb2FkIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwibmFtZSI6InRlc3QiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJxYUByZWRoYXQuY29tIiwiZ2l2ZW5fbmFtZSI6IkFCQyIsImZhbWlseV9uYW1lIjoiREVGIiwiZW1haWwiOiJ0ZXN0QHJlZGhhdC5jb20ifQ.nYtcY8XQHb8UXnYeORQhE9lObFljVfuWtNQXMtqmi_M";
    private AuthenticationFilter interceptor;
    private MockHttpRequest mockReq;

    @Override
    protected Module getGuiceOverrideModule() {
        return new AuthInterceptorTestModule();
    }

    @BeforeEach
    public void setUp() throws Exception {
        Class clazz = FakeResource.class;
        when(mockInfo.getResourceClass()).thenReturn(clazz);

        mockReq = MockHttpRequest.create("GET", "http://localhost/candlepin/status");

        ResteasyProviderFactory.pushContext(ResourceInfo.class, mockInfo);
        ResteasyProviderFactory.pushContext(HttpRequest.class, mockReq);
        when(mockRequestContext.getSecurityContext()).thenReturn(mockSecurityContext);

        config.setProperty(ConfigProperties.OAUTH_AUTHENTICATION, "false");
        config.setProperty(ConfigProperties.SSL_AUTHENTICATION, "false");
        config.setProperty(ConfigProperties.BASIC_AUTHENTICATION, "true");
        config.setProperty(ConfigProperties.TRUSTED_AUTHENTICATION, "true");
        config.setProperty(ConfigProperties.KEYCLOAK_AUTHENTICATION, "true");

        when(keycloakAdapterConfiguration.getAdapterConfig()).thenReturn(adapterConfig);
        when(adapterConfig.getAuthServerUrl()).thenReturn("https://redhat.com/auth");
        when(adapterConfig.getResource()).thenReturn("candlepin");
        when(adapterConfig.getRealm()).thenReturn("redhat");
        when(keycloakAdapterConfiguration.getKeycloakDeployment()).thenReturn(keycloakDeployment);
        when(bearerTokenRequestAuthenticator.authenticate(any())).thenReturn(AuthOutcome.AUTHENTICATED);
        when(bearerTokenRequestAuthenticator.getToken()).
            thenReturn(TokenVerifier.create(TESTTOKEN, AccessToken.class).getToken());

        interceptor = new AuthenticationFilter(config, consumerCurator, deletedConsumerCurator,
           injector, keycloakAdapterConfiguration);
        interceptor.setHttpServletRequest(mockHttpServletRequest);
    }

    private void keycloakSetup() {
        KeycloakOIDCFacade keycloakOIDCFacade = new KeycloakOIDCFacade(mockReq);
        when(usa.findByLogin(eq("qa@redhat.com"))).thenReturn(
            new User("Test", "redhat", true));
        RequestAuthenticator keycloakRequestAuthenticator = new
            CandlepinKeycloakRequestAuthenticator(keycloakOIDCFacade, mockReq, keycloakDeployment) {
            @Override
            protected boolean verifySSL() {
                //false means verification is successful
                return false;
            }

            protected BearerTokenRequestAuthenticator createBearerTokenAuthenticator() {
                // return new BearerTokenRequestAuthenticator(keycloakDeployment);
                this.deployment = keycloakDeployment;
                return bearerTokenRequestAuthenticator;
            }
        };
        when(keycloakAdapterConfiguration.getRequestAuthenticator(mockReq)).
            thenReturn(keycloakRequestAuthenticator);
    }

    private void mockResourceMethod(Method method) {
        when(mockInfo.getResourceMethod()).thenReturn(method);
    }

    private ContainerRequestContext getContext() {
        return getContext(null);
    }

    private ContainerRequestContext getContext(ResourceMethodInvoker invoker) {
        return new PostMatchContainerRequestContext(mockReq, invoker);
    }

    @Test
    public void noSecurityHoleNoPrincipalNoSsl() throws Exception {
        when(mockHttpServletRequest.isSecure()).thenReturn(false);
        Method method = FakeResource.class.getMethod("someMethod", String.class);
        mockResourceMethod(method);

        assertThrows(BadRequestException.class, () -> interceptor.filter(getContext()));
    }

    @Test
    public void noSecurityHoleNoPrincipalNoSslButOverridenByConfig() throws Exception {
        config.setProperty(ConfigProperties.AUTH_OVER_HTTP, "true");
        when(mockHttpServletRequest.isSecure()).thenReturn(false);
        Method method = FakeResource.class.getMethod("someMethod", String.class);
        mockResourceMethod(method);
        assertThrows(NotAuthorizedException.class, () -> interceptor.filter(getContext()));
        // Revert default settings
        config.setProperty(ConfigProperties.AUTH_OVER_HTTP, "false");
    }

    @Test
    public void noSecurityHoleNoPrincipal() throws Exception {
        when(mockHttpServletRequest.isSecure()).thenReturn(true);
        Method method = FakeResource.class.getMethod("someMethod", String.class);
        mockResourceMethod(method);
        assertThrows(NotAuthorizedException.class, () -> interceptor.filter(getContext()));
    }

    @Test
    public void noSecurityHole() throws Exception {
        mockReq.header("Authorization", "BASIC QWxhZGRpbjpvcGVuIHNlc2FtZQ==");

        when(usa.validateUser(eq("Aladdin"), eq("open sesame"))).thenReturn(true);
        when(usa.findByLogin(eq("Aladdin"))).thenReturn(
            new User("Aladdin", "open sesame", true));

        Method method = FakeResource.class.getMethod("someMethod", String.class);
        mockResourceMethod(method);
        interceptor.filter(getContext());

        Principal p = ResteasyProviderFactory.getContextData(Principal.class);
        assertTrue(p instanceof UserPrincipal);
    }

    @Test
    public void securityHoleWithNoAuth() throws Exception {
        Method method = FakeResource.class.getMethod("noAuthMethod", String.class);
        mockResourceMethod(method);

        interceptor.filter(getContext());

        Principal p = ResteasyProviderFactory.getContextData(Principal.class);
        assertTrue(p instanceof NoAuthPrincipal);
    }

    @Test
    public void securityHoleWithAuth() throws Exception {
        Method method = FakeResource.class.getMethod("annotatedMethod", String.class);
        mockResourceMethod(method);

        mockReq.header("Authorization", "BASIC QWxhZGRpbjpvcGVuIHNlc2FtZQ==");

        when(usa.validateUser(eq("Aladdin"), eq("open sesame"))).thenReturn(true);
        when(usa.findByLogin(eq("Aladdin"))).thenReturn(new User("Aladdin", "open sesame"));

        interceptor.filter(getContext());

        Principal p = ResteasyProviderFactory.getContextData(Principal.class);
        assertTrue(p instanceof UserPrincipal);
    }

    @Test
    public void securityHoleWithAnonAndNoPrincipal() throws Exception {
        Method method = FakeResource.class.getMethod("anonMethod", String.class);
        mockResourceMethod(method);

        interceptor.filter(getContext());

        Principal p = ResteasyProviderFactory.getContextData(Principal.class);
        assertTrue(p instanceof NoAuthPrincipal);
        // Anon should not even bother attempting to create a real principal
        verify(usa, times(0)).validateUser(anyString(), anyString());
    }

    @Test
    public void securityHoleWithAnonAndPrincipalProvided() throws Exception {
        Method method = FakeResource.class.getMethod("anonMethod", String.class);
        mockResourceMethod(method);

        mockReq.header("Authorization", "BASIC QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        interceptor.filter(getContext());

        Principal p = ResteasyProviderFactory.getContextData(Principal.class);
        assertTrue(p instanceof NoAuthPrincipal);
        // Anon should not even bother attempting to create a real principal
        verify(usa, times(0)).validateUser(anyString(), anyString());
    }

    @Test
    public void keycloakAuthAuthentication() throws Exception {
        Method method = FakeResource.class.getMethod("someMethod", String.class);
        mockResourceMethod(method);
        mockReq.header("Authorization", "Bearer " + TESTTOKEN);
        keycloakSetup();
        interceptor.filter(getContext());
        Principal p = ResteasyProviderFactory.getContextData(Principal.class);
        System.out.println(p.getName());
        assertTrue(p.getName().equals("qa@redhat.com"));
    }

    /**
     * FakeResource simply to create a Method object to pass down into
     * the interceptor.
     */
    public static class FakeResource {
        public String someMethod(String str) {
            return str;
        }

        @SecurityHole
        public String annotatedMethod(String str) {
            return str;
        }

        @SecurityHole(noAuth = true)
        public String noAuthMethod(String str) {
            return str;
        }

        @SecurityHole(anon = true)
        public String anonMethod(String str) {
            return str;
        }
    }

    private class AuthInterceptorTestModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(PermissionFactory.class).toInstance(mock(PermissionFactory.class));
            bind(ConsumerCurator.class).toInstance(mock(ConsumerCurator.class));
            bind(UserServiceAdapter.class).toInstance(usa);
            bind(KeycloakAdapterConfiguration.class).toInstance(keycloakAdapterConfiguration);
        }
    }
}

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


import org.candlepin.common.config.Configuration;
import org.candlepin.config.ConfigProperties;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.inject.Inject;
import java.io.FileInputStream;
import java.io.FileNotFoundException;




/**
 * KeycloakAdapterConfiguration to load contents from keycloak file
 */
public class KeycloakAdapterConfiguration {

    private AdapterConfig adapterConfig;
    private static Logger log = LoggerFactory.getLogger(KeycloakAdapterConfiguration.class);

    @Inject
    public KeycloakAdapterConfiguration(Configuration configuration) {

        if (configuration.getBoolean(ConfigProperties.KEYCLOAK_AUTHENTICATION)) {
            try {
                adapterConfig = KeycloakDeploymentBuilder.loadAdapterConfig(new
                        FileInputStream(configuration.getString(ConfigProperties.KEYCLOAK_FILEPATH)));
            }
            catch (FileNotFoundException e) {
                log.warn("Keycloak.json file not found", e);
            }
            catch (RuntimeException e) {
                log.warn("Unable to read keycloak.json", e);
            }

        }

    }

    public AdapterConfig getAdapterConfig() {
        return adapterConfig;
    }

}

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
package org.candlepin.resource;


import org.candlepin.auth.KeycloakAdapterConfiguration;
import org.candlepin.cache.CandlepinCache;
import org.candlepin.cache.StatusCache;
import org.candlepin.common.auth.SecurityHole;
import org.candlepin.common.config.Configuration;
import org.candlepin.common.util.VersionUtil;
import org.candlepin.config.ConfigProperties;
import org.candlepin.controller.ModeManager;
import org.candlepin.dto.api.v1.StatusDTO;
import org.candlepin.guice.CandlepinCapabilities;
import org.candlepin.model.CandlepinModeChange;
import org.candlepin.model.Rules.RulesSourceEnum;
import org.candlepin.model.RulesCurator;
import org.candlepin.policy.js.JsRunnerProvider;

import com.google.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 * Status Resource
 */
@Path("/status")
@Api("status")
public class StatusResource {
    private static Logger log = LoggerFactory.getLogger(StatusResource.class);

    /**
     * The current version of candlepin
     */
    private String version = "Unknown";

    /**
     * The current git release
     */
    private String release = "Unknown";
    private boolean standalone = true;
    private RulesCurator rulesCurator;
    private JsRunnerProvider jsProvider;
    private CandlepinCache candlepinCache;
    private ModeManager modeManager;
    private String resource = null;
    private String authUrl = null;
    private String realm = null;

    @Inject
    public StatusResource(RulesCurator rulesCurator, Configuration config, JsRunnerProvider jsProvider,
        CandlepinCache candlepinCache, ModeManager modeManager,
        KeycloakAdapterConfiguration keycloakAdapterConfiguration) {
        this.modeManager = modeManager;
        this.rulesCurator = rulesCurator;
        this.candlepinCache = candlepinCache;
        Map<String, String> map = VersionUtil.getVersionMap();
        version = map.get("version");
        release = map.get("release");

        if (config == null || !config.getBoolean(ConfigProperties.STANDALONE)) {
            standalone = false;
        }
        if (keycloakAdapterConfiguration.getAdapterConfig() != null) {
            realm = keycloakAdapterConfiguration.getAdapterConfig().getRealm();
            authUrl = keycloakAdapterConfiguration.getAdapterConfig().getAuthServerUrl();
            resource = keycloakAdapterConfiguration.getAdapterConfig().getResource();
        }
        this.jsProvider = jsProvider;
    }

    /**
     * Retrieves the Status of the System
     * <p>
     * <pre>
     * {
     *   "result" : true,
     *   "version" : "0.9.10",
     *   "rulesVersion" : "5.8",
     *   "release" : "1",
     *   "standalone" : true,
     *   "timeUTC" : [date],
     *   "managerCapabilities" : [ "cores", "ram", "instance_multiplier" ],
     *   "rulesSource" : "DEFAULT"
     * }
     * </pre>
     * <p>
     * Status to see if a server is up and running
     *
     * @return a Status object
     * @httpcode 200
     */
    @GET
    @ApiOperation(value = "Status", notes = "Returns status of the server", authorizations = {})
    @Produces({ MediaType.APPLICATION_JSON})
    @SecurityHole(noAuth = true, anon = true)
    public StatusDTO status() {
        StatusCache statusCache = candlepinCache.getStatusCache();
        StatusDTO cached = statusCache.getStatus();

        if (cached != null) {
            return cached;
        }

        /*
         * Originally this was used to indicate database connectivity being good/bad.
         * In reality it could never be false, the request would fail. This check has
         * been moved to GET /status/db.
         */
        boolean good = true;

        try {
            rulesCurator.getUpdatedFromDB();
        }
        catch (Exception e) {
            log.error("Error checking database connection", e);
            good = false;
        }

        CandlepinModeChange modeChange = modeManager.getLastCandlepinModeChange();
        CandlepinModeChange.Mode mode = modeChange.getMode();

        Iterator<CandlepinModeChange.Reason> reasonItr = modeChange.getReasons().iterator();
        CandlepinModeChange.Reason modeChangeReason = reasonItr.hasNext() ? reasonItr.next() : null;

        if (mode != CandlepinModeChange.Mode.NORMAL) {
            good = false;
        }

        CandlepinCapabilities caps = CandlepinCapabilities.getCapabilities();

        RulesSourceEnum rulesSource = jsProvider.getRulesSource();

        StatusDTO status = new StatusDTO()
            .setResult(good)
            .setVersion(version)
            .setRelease(release)
            .setStandalone(standalone)
            .setRulesVersion(jsProvider.getRulesVersion())
            .setRulesSource(rulesSource != null ? rulesSource.toString() : null)
            .setMode(mode != null ? mode.toString() : null)
            .setModeReason(modeChangeReason != null ? modeChangeReason.toString() : null)
            .setModeChangeTime(modeChange.getChangeTime())
            .setManagerCapabilities(caps)
            .setTimeUTC(new Date())
            .setResource(resource)
            .setAuthUrl(authUrl)
            .setRealm(realm);

        statusCache.setStatus(status);

        return status;
    }
}

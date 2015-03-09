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
package org.candlepin.pinsetter.tasks;

import org.candlepin.controller.PoolManager;
import org.candlepin.model.Owner;
import org.candlepin.model.OwnerCurator;
import org.candlepin.service.SubscriptionServiceAdapter;

import com.google.inject.Inject;

import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;

/**
 * The Class RegenEntitlementCertsJob.
 */
public class RegenProductEntitlementCertsJob extends KingpinJob {

    public static final String OWNER_ID = "owner_id";
    public static final String PROD_ID = "product_id";
    public static final String LAZY_REGEN = "lazy_regen";

    private PoolManager poolManager;
    private OwnerCurator ownerCurator;
    private SubscriptionServiceAdapter subAdapter;

    @Inject
    public RegenProductEntitlementCertsJob(PoolManager poolManager, OwnerCurator ownerCurator,
        SubscriptionServiceAdapter subAdapter) {

        this.poolManager = poolManager;
        this.ownerCurator = ownerCurator;
        this.subAdapter = subAdapter;
    }

    @Override
    public void toExecute(JobExecutionContext arg0) throws JobExecutionException {
        String ownerId = arg0.getJobDetail().getJobDataMap().getString(OWNER_ID);
        String productId = arg0.getJobDetail().getJobDataMap().getString(PROD_ID);
        boolean lazy = arg0.getJobDetail().getJobDataMap().getBoolean(LAZY_REGEN);

        Owner owner = this.ownerCurator.find(ownerId);

        if (owner != null) {
            this.poolManager.regenerateCertificatesOf(subAdapter, owner, productId, lazy);
        }
    }
}

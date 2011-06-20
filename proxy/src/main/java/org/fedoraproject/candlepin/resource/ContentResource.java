/**
 * Copyright (c) 2009 Red Hat, Inc.
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
package org.fedoraproject.candlepin.resource;

import java.util.List;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.fedoraproject.candlepin.exceptions.BadRequestException;
import org.fedoraproject.candlepin.model.Content;
import org.fedoraproject.candlepin.model.ContentCurator;
import org.fedoraproject.candlepin.service.UniqueIdGenerator;
import org.xnap.commons.i18n.I18n;

import com.google.inject.Inject;
/**
 * ContentResource
 */

@Path("/content")
public class ContentResource {

    private ContentCurator contentCurator;
    private I18n i18n;
    private UniqueIdGenerator idGenerator;

    @Inject
    public ContentResource(ContentCurator contentCurator, I18n i18n,
        UniqueIdGenerator idGenerator) {
        this.i18n = i18n;
        this.contentCurator = contentCurator;
        this.idGenerator = idGenerator;
    }
    
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public List<Content> list() {
        return contentCurator.listAll();
    }
    
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/{content_id}")
    public Content getContent(@PathParam("content_id") String contentId) {
        Content content = contentCurator.find(contentId);
        
        if (content == null) {
            throw new BadRequestException(
                i18n.tr("Content with id {0} could not be found", contentId));
        }
        
        return content;
    }
    
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Content createContent(Content content) {
        if (content.getId() == null || content.getId().trim().length() == 0) {
            content.setId(idGenerator.generateId());
            return contentCurator.create(content);
        }

        Content lookedUp  = contentCurator.find(content.getId());
        if (lookedUp != null) {
            return lookedUp;
        }
        return contentCurator.create(content);
    }

    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/{content_id}")
    public void remove(@PathParam("content_id") String cid) {
        Content nuke = getContent(cid);
        contentCurator.delete(nuke);
    }
}

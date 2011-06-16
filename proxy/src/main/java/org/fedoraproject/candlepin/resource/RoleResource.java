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

import org.fedoraproject.candlepin.exceptions.NotFoundException;
import org.fedoraproject.candlepin.model.Owner;
import org.fedoraproject.candlepin.model.OwnerCurator;
import org.fedoraproject.candlepin.model.OwnerPermission;
import org.fedoraproject.candlepin.model.OwnerPermissionCurator;
import org.fedoraproject.candlepin.model.Role;
import org.fedoraproject.candlepin.model.User;
import org.fedoraproject.candlepin.service.UserServiceAdapter;

import com.google.inject.Inject;

import org.jboss.resteasy.annotations.providers.jaxb.Wrapped;
import org.jboss.resteasy.spi.BadRequestException;
import org.xnap.commons.i18n.I18n;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 *
 */
@Path("/roles")
public class RoleResource {

    private UserServiceAdapter userService;
    private OwnerCurator ownerCurator;
    private OwnerPermissionCurator permissionCurator;
    private I18n i18n;

    @Inject
    public RoleResource(UserServiceAdapter userService, OwnerCurator ownerCurator,
        OwnerPermissionCurator permCurator, I18n i18n) {
        this.userService = userService;
        this.ownerCurator = ownerCurator;
        this.i18n = i18n;
        this.permissionCurator = permCurator;
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Role createRole(Role role) {

        // Attach actual owner objects to each incoming permission:
        for (OwnerPermission p : role.getPermissions()) {
            Owner temp = p.getOwner();
            Owner actual = ownerCurator.lookupByKey(temp.getKey());
            if (actual == null) {
                throw new NotFoundException(i18n.tr("No such owner: {0}", temp.getKey()));
            }
            p.setOwner(actual);
        }

        Role r = this.userService.createRole(role);
        return r;
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{role_id}")
    public Role updateRole(@PathParam("role_id") String roleId, Role role) {

        if (!roleId.equals(role.getId())) {
            throw new BadRequestException(i18n.tr("Role ID does not match path."));
        }

        Role existingRole = lookupRole(roleId);
        existingRole.setName(role.getName());

        return this.userService.updateRole(existingRole);
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{role_id}/permissions")
    public Role updateRolePermissions(@PathParam("role_id") String roleId,
        OwnerPermission permission) {

        Role existingRole = lookupRole(roleId);

        // Attach actual owner objects to each incoming permission:
        Owner temp = permission.getOwner();
        Owner real = ownerCurator.lookupByKey(temp.getKey());
        permission.setOwner(real);
        existingRole.addPermission(permission);

        Role r = this.userService.updateRole(existingRole);
        return r;
    }

    @DELETE
    @Path("{role_id}/permissions/{perm_id}")
    public Role deleteRolePermissions(@PathParam("role_id") String roleId,
                                      @PathParam("perm_id") String permissionId) {

        Role existingRole = lookupRole(roleId);
        Set<OwnerPermission> picks = new HashSet<OwnerPermission>();
        boolean found = true;
        OwnerPermission toRemove = null;
        for (OwnerPermission op : existingRole.getPermissions()) {
            if (!op.getId().equals(permissionId)) {
                picks.add(op);
            }
            else {
                found = true;
                toRemove = op;
            }

        }
        if (!found) {
            throw new NotFoundException(i18n.tr("No such permission: {0} in role: {1}",
                permissionId, roleId));
        }

        existingRole.setPermissions(picks);
        Role r = this.userService.updateRole(existingRole);
        toRemove.setOwner(null);
        permissionCurator.delete(toRemove);
        return r;
    }

    private Role lookupRole(String roleId) {
        Role role = userService.getRole(roleId);
        if (role == null) {
            throw new NotFoundException(i18n.tr("No such role: {0}", roleId));
        }
        return role;
    }

    private User lookupUser(String username) {
        User user = userService.findByLogin(username);
        if (user == null) {
            throw new NotFoundException(i18n.tr("No such user: {0}", username));
        }
        return user;
    }

    @GET
    @Path("{role_id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Role getRole(@PathParam("role_id") String roleId) {
        return lookupRole(roleId);
    }

    @DELETE
    @Path("/{role_id}")
    public void deleteRole(@PathParam("role_id") String roleId) {
        this.userService.deleteRole(roleId);
    }

    @POST
    @Path("/{role_id}/users/{username}")
    public Role addUser(@PathParam("role_id") String roleId,
        @PathParam("username") String username) {
        Role role = lookupRole(roleId);
        User user = lookupUser(username);
        userService.addUserToRole(role, user);
        return role;
    }

    @DELETE
    @Path("/{role_id}/users/{username}")
    public Role deleteUser(@PathParam("role_id") String roleId,
        @PathParam("username") String username) {
        Role role = lookupRole(roleId);
        User user = lookupUser(username);
        userService.removeUserFromRole(role, user);
        return role;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Wrapped(element = "roles")
    public List<Role> getRoles() {
        // TODO:  Add in filter options
        return userService.listRoles();
    }

}

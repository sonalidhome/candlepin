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
package org.fedoraproject.candlepin.model;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

/**
 * Represents the owner of entitlements.
 * 
 * This is akin to an organization, whereas a User is an individual account within that
 * organization.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.PROPERTY)
@Entity
@Table(name = "cp_owner")
@SequenceGenerator(name = "seq_owner", sequenceName = "seq_owner", allocationSize = 1)
public class Owner extends AbstractHibernateObject implements Serializable {
    
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "seq_owner")
    private Long id;

    @Column(nullable = false, unique = true)
    private String key;

    @Column(nullable = false)
    private String displayName;

    @OneToMany(mappedBy = "owner", targetEntity = Consumer.class)
    private Set<Consumer> consumers;
    
    // EntitlementPool is the owning side of this relationship.
    @OneToMany(mappedBy = "owner", targetEntity = Pool.class)
    private Set<Pool> pools;
    
    /*
     *  The uuid of the consumer in the upstream candlepin that maps to this owner,
     *  for entitlement syncing.
     */
    @Column(name = "upstream_uuid")
    private String upstreamUuid;
    
    /**
     * Default constructor
     */
    public Owner() {
        consumers = new HashSet<Consumer>();
        pools = new HashSet<Pool>();
    }
    
    /**
     * Constructor with required parameters.
     * 
     * @param key Owner's unique identifier
     * @param displayName Owner's name - suitable for UI
     */
    public Owner(String key, String displayName) {
        this.key = key;
        this.displayName = displayName;
        
        consumers = new HashSet<Consumer>();
        pools = new HashSet<Pool>();
    }

    /**
     * Creates an Owner with only a name
     *
     * @param name to be used for both the display name and the key
     */
    public Owner(String name) {
        this(name, name);
    }
    
    /**
     * @return the id
     */
    @Override
    public Long getId() {
        return id;
    }

    /**
     * @param id the id to set
     */
    public void setId(Long id) {
        this.id = id;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    /**
     * @return the name
     */
    public String getDisplayName() {
        return this.displayName;
    }

    /**
     * @param displayName the name to set
     */
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    /**
     * @return the consumers
     */
    @XmlTransient
    public Set<Consumer> getConsumers() {
        return consumers;
    }

    /**
     * @param consumers the consumers to set
     */
    public void setConsumers(Set<Consumer> consumers) {
        this.consumers = consumers;
    }

    /**
     * @return the entitlementPools
     */
    @XmlTransient
    public Set<Pool> getPools() {
        return pools;
    }
    /**
     * @param entitlementPools the entitlementPools to set
     */
    public void setPools(Set<Pool> entitlementPools) {
        this.pools = entitlementPools;
    }
    
    /**
     * Add a consumer to this owner
     * @param c consumer for this owner.
     */
    public void addConsumer(Consumer c) {
        c.setOwner(this);
        this.consumers.add(c);
        
    }

    /**
     * add owner to the pool, and reference to the pool.
     * @param pool EntitlementPool for this owner.
     */
    public void addEntitlementPool(Pool pool) {
        pool.setOwner(this);
        if (this.pools ==  null) {
            this.pools = new HashSet<Pool>();
        }
        this.pools.add(pool);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "Owner [name = " + getDisplayName() +
            ", key = " + getKey() +
            ", id = " + getId() + "]";
    }

    // Generated by Netbeans
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Owner other = (Owner) obj;
        if (this.id != other.id && (this.id == null || !this.id.equals(other.id))) {
            return false;
        }
        if ((this.key == null) ? (other.key != null) : !this.key.equals(other.key)) {
            return false;
        }
        if ((this.displayName == null) ? (other.displayName != null) :
            !this.displayName.equals(other.displayName)) {
            return false;
        }
        return true;
    }

    // Generated by Netbeans
    @Override
    public int hashCode() {
        int hash = 3;
        hash = 89 * hash + (this.id != null ? this.id.hashCode() : 0);
        hash = 89 * hash + (this.key != null ? this.key.hashCode() : 0);
        hash = 89 * hash + (this.displayName != null ? this.displayName.hashCode() : 0);
        return hash;
    }

    /**
     * @param upstreamUuid the upstreamUuid to set
     */
    public void setUpstreamUuid(String upstreamUuid) {
        this.upstreamUuid = upstreamUuid;
    }

    /**
     * @return the upstreamUuid
     */
    public String getUpstreamUuid() {
        return upstreamUuid;
    }
}

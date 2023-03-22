/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.ldap;

import java.util.List;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

/**
 * LDAP auth configuration options.
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@DataObject(generateConverter = true)
public class LdapAuthenticationOptions {

  private String authenticationMechanism;
  private String referral;
  private String url;
  private String authenticationQuery;
  private String filterQuery;
  private List<String> filterAttributes;

  public LdapAuthenticationOptions() {
  }

  public LdapAuthenticationOptions(JsonObject json) {
    this();
    LdapAuthenticationOptionsConverter.fromJson(json, this);
  }

  public String getAuthenticationMechanism() {
    return authenticationMechanism;
  }

  public String getReferral() {
    return referral;
  }

  public String getUrl() {
    return url;
  }

  public String getAuthenticationQuery() {
    return authenticationQuery;
  }

  /**
   * Gets a filter query that's used to lookup metadata about the authenticated user.
   *
   * @return A query that's used to filter a search to a single user
   */
  public String getFilterQuery() {
    return filterQuery;
  }

  /**
   * Gets the list of attributes that should be returned from a filtered query. These are used to populate principal
   * metadata in the {@link User} object.
   *
   * @return A list of attribute names
   */
  public List<String> getReturningAttributes() {
    return filterAttributes;
  }

  /**
   * Sets the authentication mechanism. default to 'simple' if not set
   *
   * @param authenticationMechanism
   * @return a reference to this, so the API can be used fluently
   */
  public LdapAuthenticationOptions setAuthenticationMechanism(String authenticationMechanism) {
    this.authenticationMechanism = authenticationMechanism;
    return this;
  }

  /**
   * Sets the referral property. Default to 'follow' if not set
   *
   * @param referral the referral
   * @return a reference to this, so the API can be used fluently
   */
  public LdapAuthenticationOptions setReferral(String referral) {
    this.referral = referral;
    return this;
  }

  /**
   * Sets the url to the LDAP server. The url must start with `ldap://` and a port must be specified.
   *
   * @param url the url to the server
   * @return a reference to this, so the API can be used fluently
   */
  public LdapAuthenticationOptions setUrl(String url) {
    this.url = url;
    return this;
  }

  /**
   * Sets the query to use to authenticate a user. This is used to determine the actual lookup to use when looking up a
   * user with a particular id. An example is `uid={0},ou=users,dc=foo,dc=com` - Note that the element `{0}` is
   * substituted with the user id to create the actual lookup.
   *
   * @param authenticationQuery
   * @return a reference to this, so the API can be used fluently
   */
  public LdapAuthenticationOptions setAuthenticationQuery(String authenticationQuery) {
    this.authenticationQuery = authenticationQuery;
    return this;
  }

  /**
   * Sets the filter query to record additional information about a user. This is used in conjunction with the
   * authentication query. The same pattern for inserting the user id may also be used with this query.
   *
   * @param filterQuery
   * @return a reference to this, so the API can be used fluently
   */
  public LdapAuthenticationOptions setFilterQuery(String filterQuery) {
    this.filterQuery = filterQuery;
    return this;
  }

  /**
   * Sets the attributes returned by a filter query of the user.
   *
   * @param filterAttributes
   * @return a reference to this, so the API can be used fluently
   */
  public LdapAuthenticationOptions setReturningAttributes(List<String> filterAttributes) {
    this.filterAttributes = filterAttributes;
    return this;
  }
}

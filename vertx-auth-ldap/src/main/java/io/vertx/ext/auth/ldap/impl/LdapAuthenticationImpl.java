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
package io.vertx.ext.auth.ldap.impl;

import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Objects;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import io.vertx.core.*;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.ldap.LdapAuthentication;
import io.vertx.ext.auth.ldap.LdapAuthenticationOptions;

/**
 * An implementation of {@link LdapAuthentication}.
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
public class LdapAuthenticationImpl implements LdapAuthentication {

  private static final Logger LOG = LoggerFactory.getLogger(LdapAuthenticationImpl.class);

  private static final String SIMPLE_AUTHENTICATION_MECHANISM = "simple";
  private static final String FOLLOW_REFERRAL = "follow";

  private final Vertx vertx;
  private final LdapAuthenticationOptions authenticationOptions;

  /**
   * Creates a new instance of the LdapAuthentication implementation.
   *
   * @param vertx                 A Vert.x instance
   * @param authenticationOptions Authentication options
   */
  public LdapAuthenticationImpl(Vertx vertx, LdapAuthenticationOptions authenticationOptions) {
    this.vertx = Objects.requireNonNull(vertx);
    this.authenticationOptions = Objects.requireNonNull(authenticationOptions);
  }

  @Override
  public void authenticate(JsonObject credentials, Handler<AsyncResult<User>> resultHandler) {
    authenticate(credentials).onComplete(resultHandler);
  }

  @Override
  public Future<User> authenticate(JsonObject credentials) {
    return authenticate(new UsernamePasswordCredentials(credentials));
  }

  @Override
  public Future<User> authenticate(Credentials credentials) {
    final UsernamePasswordCredentials authInfo;

    try {
      authInfo = (UsernamePasswordCredentials) credentials;
      authInfo.checkValid(null); // This checks for nulls
    } catch (RuntimeException e) {
      return Future.failedFuture(e);
    }

    return getUser(getLdapPrincipal(authInfo.getUsername()), authInfo);
  }

  /**
   * Gets an authenticated user from an LDAP source.
   *
   * @param principal   The user principal that's authenticated
   * @param credentials The username and password of the user
   * @return A user that's been authenticated against the LDAP source
   */
  private Future<User> getUser(String principal, UsernamePasswordCredentials credentials) {
    Hashtable<String, Object> environment = new Hashtable<>();
    Promise<User> promise = ((VertxInternal) vertx).promise();

    environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    environment.put(Context.PROVIDER_URL, authenticationOptions.getUrl());

    if (principal != null) {
      environment.put(Context.SECURITY_PRINCIPAL, principal);
    }

    if (credentials != null) {
      environment.put(Context.SECURITY_CREDENTIALS, credentials.getPassword());
    }

    if (authenticationOptions.getAuthenticationMechanism() == null && (principal != null || credentials != null)) {
      environment.put(Context.SECURITY_AUTHENTICATION, SIMPLE_AUTHENTICATION_MECHANISM);
    }

    environment.put(Context.REFERRAL,
        authenticationOptions.getReferral() == null ? FOLLOW_REFERRAL : authenticationOptions.getReferral());

    vertx.executeBlocking(blockingResult -> {
      try {
        LdapContext context = new InitialLdapContext(environment, null);
        User user = User.fromName(credentials.getUsername());

        // Authentication method metadata
        user.principal().put("amr", Collections.singletonList("pwd"));

        // If filter query is set, we want to store additional user metadata which can
        // be used later to authorize
        if (authenticationOptions.getFilterQuery() != null) {
          String filter = getFilterQuery(credentials.getUsername());
          SearchControls searchControls = getSearchControls();
          NamingEnumeration<SearchResult> searchResults = context.search(principal, filter, searchControls);

          if (searchResults.hasMore()) {
            SearchResult result = searchResults.next();
            NamingEnumeration<? extends Attribute> attributes = result.getAttributes().getAll();
            JsonObject metadata = user.principal();

            // If attributes are returned, store them in our User object
            while (attributes.hasMore()) {
              Attribute attribute = attributes.next();
              int attributeCount = attribute.size();
              String id = attribute.getID();

              if (attributeCount > 1) {
                JsonArray values = new JsonArray(); // Can store nulls

                for (int index = 0; index < attributeCount; index++) {
                  values.add(attribute.get(index)); // Might be a null
                }

                metadata.put(id, values);
              } else if (attributeCount == 1) {
                metadata.put(id, attribute.get(0));
              }
            }

            if (searchResults.hasMore()) {
              LOG.warn("LDAP user filter returns more than one user");
            }
          }

          searchResults.close();
        }

        context.close();
        blockingResult.complete(user);
      } catch (Throwable t) {
        blockingResult.fail(t);
      }
    }, promise);

    return promise.future();
  }

  /**
   * Gets the search controls that should be used when searching for user metadata.
   *
   * @return Search controls used when searching for user metadata
   */
  private SearchControls getSearchControls() {
    List<String> returningAttributes = authenticationOptions.getReturningAttributes();
    SearchControls searchControls = new SearchControls();

    // Support searching subtrees
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

    // Optionally, restrict attributes returned
    if (returningAttributes != null) {
      searchControls.setReturningAttributes(returningAttributes.toArray(new String[0]));
    }

    return searchControls;
  }

  /**
   * Gets the user principal with the supplied username added.
   *
   * @param principal A username
   * @return The complete LDAP principal
   */
  private String getLdapPrincipal(String principal) {
    return authenticationOptions.getAuthenticationQuery().replace("{0}", principal);
  }

  /**
   * Gets the filter used for querying the user's additional metadata.
   *
   * @param principal A username
   * @return The complete LDAP filter query
   */
  private String getFilterQuery(String principal) {
    return authenticationOptions.getFilterQuery().replace("{0}", principal);
  }
}

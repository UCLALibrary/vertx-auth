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

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.ldap.impl.LdapAuthenticationImpl;

/**
 * Factory interface for creating a LDAP {@link io.vertx.ext.auth.authentication.AuthenticationProvider}.
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@VertxGen
public interface LdapAuthentication extends AuthenticationProvider {

  /**
   * Create a LDAP authentication provider
   *
   * @param vertx The Vert.x instance
   * @param options The ldap options
   * @return The authentication provider
   */
  static LdapAuthentication create(Vertx vertx, LdapAuthenticationOptions options) {
    return new LdapAuthenticationImpl(vertx, options);
  }
}

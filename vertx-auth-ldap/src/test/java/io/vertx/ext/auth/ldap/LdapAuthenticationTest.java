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

import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;

import java.util.Arrays;
import java.util.List;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.CreateLdapServerRule;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import org.junit.runner.RunWith;

/**
 * Tests of {@link LdapAuthentication}.
 */
@CreateDS(name = "myDS", partitions = { @CreatePartition(name = "test", suffix = "dc=myorg,dc=com") })
@CreateLdapServer(transports = { @CreateTransport(protocol = "LDAP", address = "localhost") })
@ApplyLdifFiles({ "ldap.ldif" })
@RunWith(VertxUnitRunner.class)
public class LdapAuthenticationTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @ClassRule
  public static CreateLdapServerRule serverRule = new CreateLdapServerRule();

  private LdapAuthentication authProvider;
  private LdapAuthenticationOptions ldapOptions;

  /**
   * Tests that a user with the correct username and password authenticates.
   *
   * @param should A testing context
   */
  @Test
  public void testSimpleAuthenticate(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    authProvider.authenticate(credentials).onFailure(should::fail).onSuccess(user -> {
      should.assertNotNull(user);
      test.complete();
    });
  }

  /**
   * Tests that a user with the wrong password fails to authenticate.
   *
   * @param should A testing context
   */
  @Test
  public void testSimpleAuthenticateFailWrongPassword(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "wrongpassword");
    authProvider.authenticate(credentials).onSuccess(user -> should.fail("Should have failed")).onFailure(thr -> {
      should.assertNotNull(thr);
      test.complete();
    });
  }

  /**
   * Tests that a user with the wrong username fails to authenticate.
   *
   * @param should A testing context
   */
  @Test
  public void testSimpleAuthenticateFailWrongUser(TestContext should) {
    final Async test = should.async();
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("frank", "sausages");
    authProvider.authenticate(credentials).onSuccess(user -> should.fail("Should have failed")).onFailure(thr -> {
      should.assertNotNull(thr);
      test.complete();
    });
  }

  /**
   * Tests that the user returned from authentication includes LDAP attributes.
   *
   * @param should A testing context
   */
  @Test
  public void testAuthenticateWithAttributes(TestContext should) {
    final UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    final List<String> returningAttributes = Arrays.asList("amr", "cn", "sn", "objectclass");
    final Async test = should.async();

    ldapOptions.setFilterQuery("uid={0}").setReturningAttributes(returningAttributes);
    authProvider = LdapAuthentication.create(rule.vertx(), ldapOptions);
    authProvider.authenticate(credentials).onFailure(should::fail).onSuccess(user -> {
      final JsonObject attributes;

      should.assertNotNull(user);
      should.assertNotNull(attributes = user.principal());

      // Check that the attributes we request, are returned
      should.assertEquals("tim", attributes.getString("username"));
      should.assertEquals("Tim fox", attributes.getString("cn"));
      should.assertEquals("Ldap", attributes.getString("sn"));
      should.assertEquals(new JsonArray().add("pwd"), attributes.getJsonArray("amr"));
      should.assertEquals(new JsonArray().add("top").add("inetOrgPerson").add("person").add("organizationalPerson"),
          attributes.getJsonArray("objectclass"));

      // Check that the attribute we don't request, aren't returned
      should.assertNull(attributes.getString("userpassword"));

      // Wrap up test
      test.complete();
    });
  }

  /**
   * Sets up the testing environment.
   *
   * @throws Exception If there is a problem setting up testing environment
   */
  @Before
  public void setUp() throws Exception {
    ldapOptions = new LdapAuthenticationOptions().setUrl("ldap://localhost:" + serverRule.getLdapServer().getPort())
        .setAuthenticationQuery("uid={0},ou=Users,dc=myorg,dc=com");
    authProvider = LdapAuthentication.create(rule.vertx(), ldapOptions);
  }
}

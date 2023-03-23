package io.vertx.ext.auth.ldap;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.ldap.LdapAuthenticationOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.ldap.LdapAuthenticationOptions} original class using Vert.x codegen.
 */
public class LdapAuthenticationOptionsConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, LdapAuthenticationOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "authenticationMechanism":
          if (member.getValue() instanceof String) {
            obj.setAuthenticationMechanism((String)member.getValue());
          }
          break;
        case "authenticationQuery":
          if (member.getValue() instanceof String) {
            obj.setAuthenticationQuery((String)member.getValue());
          }
          break;
        case "filterQuery":
          if (member.getValue() instanceof String) {
            obj.setFilterQuery((String)member.getValue());
          }
          break;
        case "referral":
          if (member.getValue() instanceof String) {
            obj.setReferral((String)member.getValue());
          }
          break;
        case "returningAttributes":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<java.lang.String> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add((String)item);
            });
            obj.setReturningAttributes(list);
          }
          break;
        case "url":
          if (member.getValue() instanceof String) {
            obj.setUrl((String)member.getValue());
          }
          break;
      }
    }
  }

  public static void toJson(LdapAuthenticationOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(LdapAuthenticationOptions obj, java.util.Map<String, Object> json) {
    if (obj.getAuthenticationMechanism() != null) {
      json.put("authenticationMechanism", obj.getAuthenticationMechanism());
    }
    if (obj.getAuthenticationQuery() != null) {
      json.put("authenticationQuery", obj.getAuthenticationQuery());
    }
    if (obj.getFilterQuery() != null) {
      json.put("filterQuery", obj.getFilterQuery());
    }
    if (obj.getReferral() != null) {
      json.put("referral", obj.getReferral());
    }
    if (obj.getReturningAttributes() != null) {
      JsonArray array = new JsonArray();
      obj.getReturningAttributes().forEach(item -> array.add(item));
      json.put("returningAttributes", array);
    }
    if (obj.getUrl() != null) {
      json.put("url", obj.getUrl());
    }
  }
}

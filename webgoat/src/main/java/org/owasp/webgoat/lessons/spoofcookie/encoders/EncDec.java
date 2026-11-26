/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/***
 *
 * @author Angel Olle Blazquez
 *
 * RGR V3 fix (CWE-565 / CWE-345): the cookie used to be base64(hex(reverse(user + salt))) - a
 * keyless, reversible encoding that anyone could reproduce for any user name (the "salt" was only
 * cut off by length and never verified). It is now an authenticated value:
 *
 *   base64url(username) "." base64url(HMAC-SHA256(serverKey, username))
 *
 * The 256-bit server key comes from a CSPRNG and never leaves the server; decode() verifies the
 * MAC in constant time and rejects anything that was not issued by this server.
 */
public class EncDec {

  private static final String HMAC_ALG = "HmacSHA256";
  private static final byte[] KEY = newKey();
  private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64D = Base64.getUrlDecoder();

  private EncDec() {}

  private static byte[] newKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }

  private static byte[] mac(byte[] data) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALG);
      mac.init(new SecretKeySpec(KEY, HMAC_ALG));
      return mac.doFinal(data);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HMAC unavailable", e);
    }
  }

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }
    byte[] user = value.toLowerCase().getBytes(StandardCharsets.UTF_8);
    return B64.encodeToString(user) + "." + B64.encodeToString(mac(user));
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }
    int dot = encodedValue.indexOf('.');
    if (dot <= 0 || dot != encodedValue.lastIndexOf('.')) {
      throw new IllegalArgumentException("Invalid cookie format");
    }
    byte[] user = B64D.decode(encodedValue.substring(0, dot));
    byte[] tag = B64D.decode(encodedValue.substring(dot + 1));
    if (!MessageDigest.isEqual(mac(user), tag)) {
      throw new IllegalArgumentException("Invalid cookie signature");
    }
    return new String(user, StandardCharsets.UTF_8);
  }
}

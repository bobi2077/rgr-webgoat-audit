/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * RGR V5 fix (CWE-798 / CWE-1391 / CWE-330): HMAC keys for JWT signing were string literals or
 * picked from a five-word dictionary with java.util.Random. Keys are now generated per process
 * from a CSPRNG with at least the hash output length (RFC 7518 §3.2), or taken from the
 * environment when an operator supplies one.
 */
public final class JwtKeys {

  private static final SecureRandom RNG = new SecureRandom();

  private JwtKeys() {}

  /**
   * @param bytes key length in bytes (32 for HS256, 64 for HS512)
   * @return base64-encoded key, the format jjwt 0.9.x expects for String keys
   */
  public static String randomBase64Key(int bytes) {
    byte[] key = new byte[bytes];
    RNG.nextBytes(key);
    return Base64.getEncoder().encodeToString(key);
  }

  /** Key from environment variable {@code envName} (base64), otherwise a fresh random key. */
  public static String fromEnvOrRandom(String envName, int bytes) {
    String v = System.getenv(envName);
    if (v != null && Base64.getDecoder().decode(v).length >= bytes) {
      return v;
    }
    return randomBase64Key(bytes);
  }

  /** Opaque high-entropy token (e.g. refresh token), 256 bits, URL-safe. */
  public static String randomToken() {
    byte[] b = new byte[32];
    RNG.nextBytes(b);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }
}

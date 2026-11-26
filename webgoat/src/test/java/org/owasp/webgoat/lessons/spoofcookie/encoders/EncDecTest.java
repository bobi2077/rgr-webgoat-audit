/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;



/***
 *
 * @author Angel Olle Blazquez
 *
 */

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/** RGR V3: EncDec now produces an HMAC-authenticated value instead of a reversible encoding. */
class EncDecTest {

  @ParameterizedTest
  @DisplayName("Round trip encode/decode")
  @ValueSource(strings = {"webgoat", "admin", "tom"})
  void roundTrip(String user) {
    assertThat(EncDec.decode(EncDec.encode(user))).isEqualTo(user);
  }

  @ParameterizedTest
  @DisplayName("Legacy (keyless) cookie values are rejected")
  @MethodSource("legacyValues")
  void legacyValuesRejected(String legacy) {
    assertThatThrownBy(() -> EncDec.decode(legacy)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("Tampered user part is rejected")
  void tamperedRejected() {
    String webgoat = EncDec.encode("webgoat");
    String forged = EncDec.encode("tom").split("\\.")[0] + "." + webgoat.split("\\.")[1];
    assertThatThrownBy(() -> EncDec.decode(forged)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("null encode test")
  void testNullEncode() {
    assertThat(EncDec.encode(null)).isNull();
  }

  @Test
  @DisplayName("null decode test")
  void testNullDecode() {
    assertThat(EncDec.decode(null)).isNull();
  }

  private static Stream<Arguments> legacyValues() {
    return Stream.of(
        Arguments.of("NjI2MTcwNGI3YTQxNGE1OTU2NzQ3NDYxNmY2NzYyNjU3Nw=="),
        Arguments.of("NjI2MTcwNGI3YTQxNGE1OTU2NzQ2ZTY5NmQ2NDYx"),
        Arguments.of("NjI2MTcwNGI3YTQxNGE1OTU2NzQ2ZDZmNzQ="));
  }
}

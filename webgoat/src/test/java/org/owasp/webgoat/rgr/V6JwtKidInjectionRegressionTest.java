package org.owasp.webgoat.rgr;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsStringIgnoringCase;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * RGR V6 - CWE-89 (leading to CWE-347): the JWT "kid" header was concatenated into an SQL query
 * used to look up the verification key, so the caller could choose the key that verifies its own
 * token. SQL error text was also echoed to the client (CWE-209).
 */
class V6JwtKidInjectionRegressionTest extends LessonTest {

  private static String tokenWithKid(String kid, String signingKey) {
    return Jwts.builder()
        .setHeaderParam("kid", kid)
        .setClaims(Map.of("username", "Tom"))
        .signWith(SignatureAlgorithm.HS512, signingKey)
        .compact();
  }

  @Test
  @DisplayName("kid with UNION SELECT supplying attacker key must be rejected")
  void unionInjectedKeyIsRejected() throws Exception {
    String key = "deletingTom";
    String kid = "x' UNION SELECT '" + key + "' FROM INFORMATION_SCHEMA.SYSTEM_USERS --";
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", tokenWithKid(kid, key)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  @DisplayName("Malformed kid must not leak SQL engine error text")
  void sqlErrorsAreNotReflected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/kid/delete")
                .param("token", tokenWithKid("'", "whatever")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(
            jsonPath(
                "$.output",
                anyOf(
                    nullValue(),
                    not(
                        anyOf(
                            containsStringIgnoringCase("unexpected"),
                            containsStringIgnoringCase("SQL"),
                            containsStringIgnoringCase("statement"))))));
  }
}

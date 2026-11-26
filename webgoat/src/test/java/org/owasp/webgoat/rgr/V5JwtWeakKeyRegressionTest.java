package org.owasp.webgoat.rgr;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import jakarta.servlet.http.Cookie;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * RGR V5 - CWE-798 / CWE-1391 / CWE-330: HMAC signing keys were hard-coded or chosen from a tiny
 * dictionary, so an attacker can recover the key offline and mint arbitrary valid tokens.
 */
class V5JwtWeakKeyRegressionTest extends LessonTest {

  /** Every candidate an attacker could learn from the public source code. */
  private static final String[] KNOWN_WEAK_KEYS = {
    "victory", "business", "available", "shipping", "washington"
  };

  private static final String LEAKED_REFRESH_KEY = "bm5n3SkxCX4kKRy4";

  @Test
  @DisplayName("/JWT/secret: token signed with any dictionary word must be rejected")
  void secretEndpointRejectsDictionaryKeys() throws Exception {
    for (String word : KNOWN_WEAK_KEYS) {
      String token =
          Jwts.builder()
              .setIssuer("WebGoat Token Builder")
              .setAudience("webgoat.org")
              .setIssuedAt(new Date())
              .setExpiration(Date.from(Instant.now().plusSeconds(60)))
              .setSubject("tom@webgoat.org")
              .claim("username", "WebGoat")
              .claim("Email", "tom@webgoat.org")
              .claim("Role", new String[] {"Manager", "Project Administrator"})
              .signWith(SignatureAlgorithm.HS256, TextCodec.BASE64.encode(word))
              .compact();
      mockMvc
          .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", is(false)));
    }
  }

  @Test
  @DisplayName("/JWT/votings: admin token signed with a dictionary word must be rejected")
  void votesRejectDictionaryKeys() throws Exception {
    for (String word : KNOWN_WEAK_KEYS) {
      Claims c = Jwts.claims();
      c.put("admin", "true");
      c.put("user", "Tom");
      String token =
          Jwts.builder()
              .setClaims(c)
              .signWith(SignatureAlgorithm.HS512, TextCodec.BASE64.encode(word))
              .compact();
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/JWT/votings")
                  .contentType(MediaType.APPLICATION_JSON)
                  .cookie(new Cookie("access_token", token)))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", is(false)));
    }
  }

  @Test
  @DisplayName("/JWT/refresh: token signed with the key published in source must be rejected")
  void refreshRejectsKeyFromSource() throws Exception {
    Claims c = Jwts.claims();
    c.put("admin", "false");
    c.put("user", "Tom");
    String token =
        Jwts.builder().setClaims(c).signWith(SignatureAlgorithm.HS512, LEAKED_REFRESH_KEY).compact();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

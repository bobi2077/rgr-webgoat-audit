package org.owasp.webgoat.rgr;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * RGR V4 - CWE-347: endpoints used {@code Jwts.parser().parse()}, which accepts unsigned tokens
 * with {@code "alg":"none"}, so any claim (e.g. admin=true, user=Tom) could be asserted.
 */
class V4JwtUnsignedTokenRegressionTest extends LessonTest {

  private static String unsigned(Object admin, String user) {
    Claims c = Jwts.claims();
    c.put("admin", admin);
    c.put("user", user);
    return Jwts.builder().setClaims(c).setHeaderParam("alg", "none").compact();
  }

  @Test
  @DisplayName("Votes reset: unsigned alg=none admin token must be rejected")
  void votesResetRejectsUnsignedToken() throws Exception {
    for (Object admin : new Object[] {"true", Boolean.TRUE}) {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/JWT/votings")
                  .contentType(MediaType.APPLICATION_JSON)
                  .cookie(new Cookie("access_token", unsigned(admin, "Tom"))))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", is(false)));
    }
  }

  @Test
  @DisplayName("Refresh checkout: unsigned alg=none token for Tom must be rejected")
  void refreshCheckoutRejectsUnsignedToken() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + unsigned("false", "Tom")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  @DisplayName("Votes list: unsigned token must not unlock the user view")
  void votesListTreatsUnsignedAsGuest() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/JWT/votings")
                .cookie(new Cookie("access_token", unsigned("false", "Tom"))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].numberOfVotes").doesNotExist());
  }
}

package org.owasp.webgoat.rgr;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.hijacksession.cas.HijackSessionAuthenticationProvider;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * RGR V2 - CWE-330 / CWE-341: session identifiers were a sequential counter plus a timestamp, so
 * neighbouring (other users') identifiers could be predicted.
 */
class V2SessionIdRegressionTest extends LessonTest {

  private static String newId() {
    return HijackSessionAuthenticationProvider.AUTHENTICATION_SUPPLIER.get().getId();
  }

  @Test
  @DisplayName("Session id must not have the '<counter>-<epochMillis>' structure")
  void idIsNotCounterPlusTimestamp() {
    assertThat(newId()).doesNotMatch("^\d+-\d{13}$");
  }

  @Test
  @DisplayName("Consecutive ids must not share a predictable prefix/counter relation")
  void consecutiveIdsAreNotSequential() {
    String a = newId();
    String b = newId();
    assertThat(a).isNotEqualTo(b);
    if (a.contains("-") && b.contains("-")) {
      String pa = a.substring(0, a.indexOf('-'));
      String pb = b.substring(0, b.indexOf('-'));
      if (pa.matches("\d+") && pb.matches("\d+")) {
        assertThat(Long.parseLong(pb) - Long.parseLong(pa)).isNotEqualTo(1L);
      }
    }
  }

  @Test
  @DisplayName("Id carries >= 128 bits of entropy (>= 22 base64url chars) and is unique")
  void idsAreLongAndUnique() {
    Set<String> seen = new HashSet<>();
    for (int i = 0; i < 2000; i++) {
      String id = newId();
      assertThat(id).matches("^[A-Za-z0-9_-]{22,}$");
      assertThat(seen.add(id)).isTrue();
    }
  }

  @Test
  @DisplayName("Session cookie is HttpOnly")
  void cookieIsHttpOnly() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/HijackSession/login")
                .param("username", "webgoat")
                .param("password", "webgoat"))
        .andExpect(cookie().httpOnly("hijack_cookie", true));
  }
}

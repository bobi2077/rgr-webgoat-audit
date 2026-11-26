package org.owasp.webgoat.rgr;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * RGR V3 - CWE-565 / CWE-345: the authentication cookie was a reversible encoding of the user
 * name without any integrity protection, so a cookie for another user could be produced offline.
 */
class V3CookieIntegrityRegressionTest extends LessonTest {

  private static final String COOKIE = "spoof_auth";

  /** Builds a cookie the way the original (keyless) scheme did: base64(hex(reverse(u+pad))). */
  private static String legacyEncode(String user) {
    String s = new StringBuilder(user + "AAAAAAAAAA").reverse().toString();
    StringBuilder hex = new StringBuilder();
    for (byte b : s.getBytes(StandardCharsets.UTF_8)) hex.append(String.format("%02x", b));
    return Base64.getEncoder().encodeToString(hex.toString().getBytes(StandardCharsets.UTF_8));
  }

  private void assertNotLoggedInAsTom(String cookieValue) throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SpoofCookie/login")
                .cookie(new Cookie(COOKIE, cookieValue))
                .param("username", "")
                .param("password", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  @DisplayName("Cookie built offline for 'tom' (no server key) must be rejected")
  void forgedCookieRejected() throws Exception {
    assertNotLoggedInAsTom(legacyEncode("tom"));
  }

  @Test
  @DisplayName("Legitimate cookie of 'webgoat' modified to 'tom' must be rejected")
  void tamperedCookieRejected() throws Exception {
    MvcResult r =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/SpoofCookie/login")
                    .param("username", "webgoat")
                    .param("password", "webgoat"))
            .andExpect(cookie().httpOnly(COOKIE, true))
            .andReturn();
    String legit = r.getResponse().getCookie(COOKIE).getValue();
    String tampered = legit.replaceFirst("^[^.]*", Base64.getUrlEncoder().withoutPadding()
        .encodeToString("tom".getBytes(StandardCharsets.UTF_8)));
    assertNotLoggedInAsTom(tampered);
    assertNotLoggedInAsTom(legacyEncode("tom").substring(0, 8) + legit);
  }
}

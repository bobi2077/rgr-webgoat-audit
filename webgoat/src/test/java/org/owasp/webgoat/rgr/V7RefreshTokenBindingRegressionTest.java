package org.owasp.webgoat.rgr;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.lang.reflect.Field;
import java.util.Date;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.jwt.JWTRefreshEndpoint;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * RGR V7 - CWE-287 / CWE-613: a refresh token was not bound to the user it was issued to, and
 * expired access tokens of any user were accepted, so Jerry's refresh token could mint a fresh
 * access token for Tom (from Tom's expired/leaked token).
 */
class V7RefreshTokenBindingRegressionTest extends LessonTest {

  private final ObjectMapper om = new ObjectMapper();

  /** Server signing key, read reflectively (simulates a token legitimately issued earlier). */
  private static String serverKey() throws Exception {
    Field f = JWTRefreshEndpoint.class.getDeclaredField("JWT_PASSWORD");
    f.setAccessible(true);
    return (String) f.get(null);
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> loginJerry() throws Exception {
    String body =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        om.writeValueAsString(
                            Map.of("user", "Jerry", "password", JWTRefreshEndpoint.PASSWORD))))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    return om.readValue(body, Map.class);
  }

  @Test
  @DisplayName("Jerry's refresh token must not refresh Tom's expired access token")
  void refreshTokenIsBoundToItsOwner() throws Exception {
    String jerryRefresh = (String) loginJerry().get("refresh_token");
    String tomExpired =
        Jwts.builder()
            .setClaims(Map.of("admin", "false", "user", "Tom"))
            .setIssuedAt(new Date(1526131411000L))
            .setExpiration(new Date(1526217811000L))
            .signWith(SignatureAlgorithm.HS512, serverKey())
            .compact();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .header("Authorization", "Bearer " + tomExpired)
                .contentType(MediaType.APPLICATION_JSON)
                .content(om.writeValueAsString(Map.of("refresh_token", jerryRefresh))))
        .andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("Owner can still refresh, and a refresh token is single-use")
  void ownerCanRefreshOnce() throws Exception {
    Map<String, Object> t = loginJerry();
    var req =
        MockMvcRequestBuilders.post("/JWT/refresh/newToken")
            .header("Authorization", "Bearer " + t.get("access_token"))
            .contentType(MediaType.APPLICATION_JSON)
            .content(om.writeValueAsString(Map.of("refresh_token", t.get("refresh_token"))));
    mockMvc.perform(req).andExpect(status().isOk());
    mockMvc.perform(req).andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("Issued access tokens carry an expiry (exp) claim")
  void accessTokenHasExpiry() throws Exception {
    String access = (String) loginJerry().get("access_token");
    var claims = Jwts.parser().setSigningKey(serverKey()).parseClaimsJws(access).getBody();
    assertThat(claims.getExpiration()).isNotNull();
  }
}

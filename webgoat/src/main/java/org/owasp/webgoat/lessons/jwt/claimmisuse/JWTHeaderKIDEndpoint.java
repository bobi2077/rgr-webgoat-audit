/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.impl.TextCodec;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "jwt-kid-hint1",
  "jwt-kid-hint2",
  "jwt-kid-hint3",
  "jwt-kid-hint4",
  "jwt-kid-hint5",
  "jwt-kid-hint6"
})
@RequestMapping("/JWT/")
public class JWTHeaderKIDEndpoint implements AssignmentEndpoint {
  private final LessonDataSource dataSource;
  private static final Pattern KID_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{1,64}$");

  private JWTHeaderKIDEndpoint(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("kid/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("kid/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    } else {
      try {
        Jwt jwt =
            Jwts.parser()
                .setSigningKeyResolver(
                    new SigningKeyResolverAdapter() {
                      @Override
                      public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                        // RGR V6 fix (CWE-89): "kid" is attacker-controlled. Validate its shape and
                        // bind it as a parameter, so it can only SELECT an existing server key.
                        final Object kidObj = header.get("kid");
                        if (!(kidObj instanceof String kid) || !KID_PATTERN.matcher(kid).matches()) {
                          throw new SignatureException("Unknown key id");
                        }
                        try (var connection = dataSource.getConnection();
                            PreparedStatement ps =
                                connection.prepareStatement(
                                    "SELECT key FROM jwt_keys WHERE id = ?")) {
                          ps.setString(1, kid);
                          try (ResultSet rs = ps.executeQuery()) {
                            if (rs.next()) {
                              return TextCodec.BASE64.decode(rs.getString(1));
                            }
                          }
                        } catch (SQLException e) {
                          // RGR V6 fix (CWE-209): never reflect database errors to the client.
                          throw new SignatureException("Key lookup failed");
                        }
                        throw new SignatureException("Unknown key id");
                      }
                    })
                .parseClaimsJws(token);
        Claims claims = (Claims) jwt.getBody();
        String username = (String) claims.get("username");
        if ("Jerry".equals(username)) {
          return failed(this).feedback("jwt-final-jerry-account").build();
        }
        if ("Tom".equals(username)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-final-not-tom").build();
        }
      } catch (JwtException | IllegalArgumentException e) {
        return failed(this).feedback("jwt-invalid-token").build();
      }
    }
  }
}

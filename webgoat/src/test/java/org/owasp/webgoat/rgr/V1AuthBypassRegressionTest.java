package org.owasp.webgoat.rgr;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.lessons.authbypass.AccountVerificationHelper;

/**
 * RGR V1 - CWE-287 / CWE-288: security-question verification could be satisfied by submitting
 * parameters with unexpected names (none of the expected answers were actually checked).
 */
class V1AuthBypassRegressionTest {

  private static final int USER_ID = 1223445;
  private final AccountVerificationHelper helper = new AccountVerificationHelper();

  private static HashMap<String, String> answers(String... kv) {
    var m = new HashMap<String, String>();
    for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
    return m;
  }

  @Test
  @DisplayName("Renamed answer parameters must NOT verify the account")
  void renamedParametersAreRejected() {
    assertThat(helper.verifyAccount(USER_ID, answers("secQuestion2", "x", "secQuestion3", "y")))
        .isFalse();
  }

  @Test
  @DisplayName("Only one expected answer plus an extra parameter must NOT verify")
  void partialAnswersAreRejected() {
    assertThat(
            helper.verifyAccount(
                USER_ID, answers("secQuestion0", "Dr. Watson", "secQuestionX", "anything")))
        .isFalse();
  }

  @Test
  @DisplayName("Wrong answers must NOT verify")
  void wrongAnswersAreRejected() {
    assertThat(
            helper.verifyAccount(
                USER_ID, answers("secQuestion0", "wrong", "secQuestion1", "Baker Street")))
        .isFalse();
  }

  @Test
  @DisplayName("Unknown user id must NOT verify even with correct answers")
  void unknownUserIsRejected() {
    assertThat(
            helper.verifyAccount(
                42, answers("secQuestion0", "Dr. Watson", "secQuestion1", "Baker Street")))
        .isFalse();
  }

  @Test
  @DisplayName("Correct answers for the correct user still verify (no functional regression)")
  void correctAnswersVerify() {
    assertThat(
            helper.verifyAccount(
                USER_ID, answers("secQuestion0", "Dr. Watson", "secQuestion1", "Baker Street")))
        .isTrue();
  }
}

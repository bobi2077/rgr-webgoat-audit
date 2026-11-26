/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/** Created by appsec on 7/18/17. */
public class AccountVerificationHelper {

  // simulating database storage of verification credentials
  private static final Integer verifyUserId = 1223445;
  private static final Map<String, String> userSecQuestions = new HashMap<>();

  static {
    userSecQuestions.put("secQuestion0", "Dr. Watson");
    userSecQuestions.put("secQuestion1", "Baker Street");
  }

  private static final Map<Integer, Map> secQuestionStore = new HashMap<>();

  static {
    secQuestionStore.put(verifyUserId, userSecQuestions);
  }

  // end 'data store set up'

  // this is to aid feedback in the attack process and is not intended to be part of the
  // 'vulnerable' code
  public boolean didUserLikelylCheat(HashMap<String, String> submittedAnswers) {
    boolean likely = false;

    if (submittedAnswers.size() == secQuestionStore.get(verifyUserId).size()) {
      likely = true;
    }

    if ((submittedAnswers.containsKey("secQuestion0")
            && submittedAnswers
                .get("secQuestion0")
                .equals(secQuestionStore.get(verifyUserId).get("secQuestion0")))
        && (submittedAnswers.containsKey("secQuestion1")
            && submittedAnswers
                .get("secQuestion1")
                .equals(secQuestionStore.get(verifyUserId).get("secQuestion1")))) {
      likely = true;
    } else {
      likely = false;
    }

    return likely;
  }

  // end of cheating check ... the method below is the one of real interest. Can you find the flaw?

  /**
   * RGR V1 fix (CWE-287 / CWE-288). The original check only compared answers whose parameter names
   * happened to be present, so renamed parameters skipped every comparison ("fail open"). Now the
   * record of the <em>requested</em> user is used, the submitted key set must be exactly the
   * expected one, and every answer is compared in constant time ("fail closed").
   */
  @SuppressWarnings("unchecked")
  public boolean verifyAccount(Integer userId, HashMap<String, String> submittedQuestions) {
    if (userId == null || submittedQuestions == null) {
      return false;
    }
    Map<String, String> expected = secQuestionStore.get(userId);
    if (expected == null || !submittedQuestions.keySet().equals(expected.keySet())) {
      return false;
    }
    boolean allMatch = true;
    for (Map.Entry<String, String> e : expected.entrySet()) {
      String given = submittedQuestions.get(e.getKey());
      allMatch &=
          given != null
              && MessageDigest.isEqual(
                  given.getBytes(StandardCharsets.UTF_8),
                  e.getValue().getBytes(StandardCharsets.UTF_8));
    }
    return allMatch;
  }
}

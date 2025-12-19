package ca.bc.gov.nrs.api.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for cookie SameSite attribute handling in SecurityHeadersFilter.
 * Tests the fixCookieHeader method logic directly.
 */
class SecurityHeadersFilterCookieTest {

  private SecurityHeadersFilter filter = new SecurityHeadersFilter();

  /**
   * Calls the package-private fixCookieHeader method for testing.
   */
  private String fixCookieHeader(String cookie) {
    return filter.fixCookieHeader(cookie);
  }

  @Test
  void testCookieWithoutSameSite() {
    String cookie = "sessionId=abc123";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should add SameSite=Strict");
    assertEquals("sessionId=abc123; SameSite=Strict", result);
  }

  @Test
  void testCookieWithSameSiteNone() {
    String cookie = "sessionId=abc123; SameSite=None";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should replace SameSite=None with Strict");
    assertFalse(result.contains("SameSite=None"), "Should not contain SameSite=None");
  }

  @Test
  void testCookieWithSameSiteLax() {
    String cookie = "sessionId=abc123; SameSite=Lax";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should replace SameSite=Lax with Strict");
    assertFalse(result.contains("SameSite=Lax"), "Should not contain SameSite=Lax");
  }

  @Test
  void testCookieWithSameSiteStrict() {
    String cookie = "sessionId=abc123; SameSite=Strict";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should keep SameSite=Strict");
    // Should not duplicate - count occurrences using indexOf
    int count = 0;
    int index = 0;
    String search = "SameSite=Strict";
    while ((index = result.indexOf(search, index)) != -1) {
      count++;
      index += search.length();
    }
    assertEquals(1, count, "Should have exactly one SameSite=Strict attribute");
  }

  @Test
  void testCookieWithHttpOnly() {
    String cookie = "sessionId=abc123; HttpOnly";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should add SameSite=Strict");
    assertTrue(result.contains("HttpOnly"), "Should preserve HttpOnly");
    // Verify both attributes are present (ordering is implementation-specific)
  }

  @Test
  void testCookieWithSecure() {
    String cookie = "sessionId=abc123; Secure";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should add SameSite=Strict");
    assertTrue(result.contains("Secure"), "Should preserve Secure");
    // Verify both attributes are present (ordering is implementation-specific)
  }

  @Test
  void testCookieWithPath() {
    String cookie = "sessionId=abc123; Path=/";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should add SameSite=Strict");
    assertTrue(result.contains("Path=/"), "Should preserve Path");
    // Verify both attributes are present (ordering is implementation-specific)
  }

  @Test
  void testCookieWithMultipleAttributes() {
    // Test with HttpOnly, Secure, and Path - should add SameSite
    String cookie = "sessionId=abc123; Secure; HttpOnly; Path=/";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should add SameSite=Strict");
    assertTrue(result.contains("Secure"), "Should preserve Secure");
    assertTrue(result.contains("HttpOnly"), "Should preserve HttpOnly");
    assertTrue(result.contains("Path=/"), "Should preserve Path");
    // Verify all attributes are present (ordering is implementation-specific)
  }

  @Test
  void testCookieWithCaseInsensitiveSameSite() {
    String cookie = "sessionId=abc123; samesite=none";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should replace case-insensitive SameSite=None");
    assertFalse(result.toLowerCase().contains("samesite=none"), "Should not contain SameSite=None");
  }

  @Test
  void testCookieWithSpacesInSameSite() {
    String cookie = "sessionId=abc123; SameSite = None";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should handle spaces in SameSite attribute");
    // Verify the original value with spaces was replaced, not just added
    assertFalse(result.contains("= None"), "Should not contain original SameSite = None");
    assertFalse(result.toLowerCase().contains("samesite = none"), "Should not contain original SameSite = None (case-insensitive)");
  }

  @Test
  void testNullCookie() {
    String result = fixCookieHeader(null);
    assertNull(result, "Should return null for null input");
  }

  @Test
  void testEmptyCookie() {
    String result = fixCookieHeader("");
    assertEquals("", result, "Should return empty string for empty input");
  }
}

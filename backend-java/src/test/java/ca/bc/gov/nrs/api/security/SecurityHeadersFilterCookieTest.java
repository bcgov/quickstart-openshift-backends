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
    // Should not duplicate
    assertEquals(1, (result.length() - result.replace("SameSite=Strict", "").length()) / "SameSite=Strict".length());
  }

  @Test
  void testCookieWithHttpOnly() {
    String cookie = "sessionId=abc123; HttpOnly";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should add SameSite=Strict");
    assertTrue(result.contains("HttpOnly"), "Should preserve HttpOnly");
    // SameSite should come before HttpOnly
    int sameSiteIndex = result.indexOf("SameSite=Strict");
    int httpOnlyIndex = result.indexOf("HttpOnly");
    assertTrue(sameSiteIndex < httpOnlyIndex, "SameSite should come before HttpOnly");
  }

  @Test
  void testCookieWithSecure() {
    String cookie = "sessionId=abc123; Secure";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should add SameSite=Strict");
    assertTrue(result.contains("Secure"), "Should preserve Secure");
    // SameSite should come before Secure
    int sameSiteIndex = result.indexOf("SameSite=Strict");
    int secureIndex = result.indexOf("Secure");
    assertTrue(sameSiteIndex < secureIndex, "SameSite should come before Secure");
  }

  @Test
  void testCookieWithPath() {
    String cookie = "sessionId=abc123; Path=/";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should add SameSite=Strict");
    assertTrue(result.contains("Path=/"), "Should preserve Path");
    // SameSite should come before Path
    int sameSiteIndex = result.indexOf("SameSite=Strict");
    int pathIndex = result.indexOf("Path=");
    assertTrue(sameSiteIndex < pathIndex, "SameSite should come before Path");
  }

  @Test
  void testCookieWithMultipleAttributes() {
    // Test with HttpOnly, Secure, and Path - should insert before the earliest one
    String cookie = "sessionId=abc123; Secure; HttpOnly; Path=/";
    String result = fixCookieHeader(cookie);
    assertTrue(result.contains("SameSite=Strict"), "Should add SameSite=Strict");
    assertTrue(result.contains("Secure"), "Should preserve Secure");
    assertTrue(result.contains("HttpOnly"), "Should preserve HttpOnly");
    assertTrue(result.contains("Path=/"), "Should preserve Path");
    // SameSite should come before Secure (the earliest attribute)
    int sameSiteIndex = result.indexOf("SameSite=Strict");
    int secureIndex = result.indexOf("Secure");
    assertTrue(sameSiteIndex < secureIndex, "SameSite should come before Secure");
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

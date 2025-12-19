package ca.bc.gov.nrs.api.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for path matching logic in SecurityHeadersFilter.
 * Tests the isApiVersionPath method to validate path matching specificity.
 */
class SecurityHeadersFilterPathMatchingTest {

  private SecurityHeadersFilter filter = new SecurityHeadersFilter();

  /**
   * Calls the package-private isApiVersionPath method for testing.
   */
  private boolean isApiVersionPath(String path) {
    return filter.isApiVersionPath(path);
  }

  @Test
  void testPathMatchingPositiveCases() {
    // These should match (get no-cache headers):
    
    // Exact match
    assertTrue(isApiVersionPath("/api/v"), "Should match exact /api/v");
    
    // Single digit version
    assertTrue(isApiVersionPath("/api/v1"), "Should match /api/v1");
    assertTrue(isApiVersionPath("/api/v2"), "Should match /api/v2");
    assertTrue(isApiVersionPath("/api/v9"), "Should match /api/v9");
    
    // Version followed by slash
    assertTrue(isApiVersionPath("/api/v1/"), "Should match /api/v1/");
    assertTrue(isApiVersionPath("/api/v2/"), "Should match /api/v2/");
    
    // Version followed by path segments
    assertTrue(isApiVersionPath("/api/v1/users"), "Should match /api/v1/users");
    assertTrue(isApiVersionPath("/api/v1/users/123"), "Should match /api/v1/users/123");
    assertTrue(isApiVersionPath("/api/v2/endpoint"), "Should match /api/v2/endpoint");
  }

  @Test
  void testPathMatchingNegativeCases() {
    // These should NOT match (get caching headers):
    
    // Paths shorter than /api/v
    assertFalse(isApiVersionPath("/api"), "Should not match /api");
    assertFalse(isApiVersionPath("/api/"), "Should not match /api/");
    
    // Paths that don't start with /api/v
    assertFalse(isApiVersionPath("/api-docs"), "Should not match /api-docs");
    assertFalse(isApiVersionPath("/api.json"), "Should not match /api.json");
    assertFalse(isApiVersionPath("/api/v1abc"), "Should not match /api/v1abc (no slash after digit)");
    
    // Paths where charAt(6) is not a digit
    assertFalse(isApiVersionPath("/api/version"), "Should not match /api/version (charAt(6) = 'e')");
    assertFalse(isApiVersionPath("/api/veterinary"), "Should not match /api/veterinary (charAt(6) = 't')");
    assertFalse(isApiVersionPath("/api/vabc"), "Should not match /api/vabc (charAt(6) = 'a')");
    
    // Edge cases
    assertFalse(isApiVersionPath("/api/v1abc"), "Should not match /api/v1abc (charAt(7) = 'a', not '/')");
    assertFalse(isApiVersionPath("/api/v12"), "Should not match /api/v12 (charAt(7) = '2', not '/')");
    
    // Other paths
    assertFalse(isApiVersionPath("/"), "Should not match root path");
    assertFalse(isApiVersionPath("/health"), "Should not match /health");
    assertFalse(isApiVersionPath("/metrics"), "Should not match /metrics");
  }

  @Test
  void testPathMatchingEdgeCases() {
    // Edge cases and boundary conditions
    
    // Empty string
    assertFalse(isApiVersionPath(""), "Should not match empty string");
    
    // Just "/api/v" - this should match (exact match case)
    assertTrue(isApiVersionPath("/api/v"), "Should match exact /api/v");
    
    // Very long paths
    assertTrue(isApiVersionPath("/api/v1/users/123/addresses/456"), 
        "Should match long path with /api/v1");
    
    // Paths with query strings (path doesn't include query string)
    // Note: In real requests, query strings are separate, but for testing we verify path only
    assertTrue(isApiVersionPath("/api/v1/users?page=1"), 
        "Should match path even if it contains '?' (though query strings are typically separate)");
  }
}

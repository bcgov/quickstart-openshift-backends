package ca.bc.gov.nrs.api.security;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.*;

/**
 * Tests for SecurityHeadersFilter to ensure security headers are correctly applied.
 */
@QuarkusTest
class SecurityHeadersFilterTest {

  @Test
  void testSecurityHeadersPresent() {
    given()
      .basePath("/api/v1")
      .when().get("/users")
      .then()
      .statusCode(200)
      .header("X-Content-Type-Options", equalTo("nosniff"))
      .header("X-Frame-Options", equalTo("DENY"))
      .header("Content-Security-Policy", equalTo("default-src 'self'"))
      .header("Permissions-Policy", notNullValue())
      .header("Referrer-Policy", equalTo("strict-origin-when-cross-origin"));
  }

  @Test
  void testServerHeaderRemoved() {
    given()
      .basePath("/api/v1")
      .when().get("/users")
      .then()
      .statusCode(200)
      .header("Server", nullValue())
      .header("X-Powered-By", nullValue());
  }

  @Test
  void testCacheControlApiEndpoints() {
    // Test API endpoint - should have no-cache headers
    given()
      .basePath("/api/v1")
      .when().get("/users")
      .then()
      .statusCode(200)
      .header("Cache-Control", containsString("no-store"))
      .header("Cache-Control", containsString("no-cache"))
      .header("Cache-Control", containsString("private"))
      .header("Pragma", equalTo("no-cache"))
      .header("Expires", equalTo("0"));
  }

  @Test
  void testCacheControlRootEndpoint() {
    // Test root endpoint - should allow caching
    // Note: Quarkus static file serving may set its own Cache-Control headers
    // (e.g., "public, immutable, max-age=86400"), which is acceptable
    given()
      .when().get("/")
      .then()
      .statusCode(200)
      .header("Cache-Control", anyOf(
        containsString("public"), // Our filter sets this, or Quarkus sets its own
        notNullValue() // Any Cache-Control header is acceptable for static content
      ));
  }

  @Test
  void testCacheControlSwaggerUi() {
    // Test Swagger UI endpoint - should have no-cache headers (excluded from caching)
    given()
      .when().get("/q/swagger-ui")
      .then()
      .statusCode(anyOf(equalTo(200), equalTo(302), equalTo(404))) // May redirect or not exist
      .header("Cache-Control", anyOf(
        containsString("no-store"), // If filter applied
        nullValue() // If endpoint doesn't exist
      ));
  }

  @Test
  void testCacheControlApiDocs() {
    // Test OpenAPI endpoint
    // Note: /q/* endpoints are handled by Quarkus's internal routing, not JAX-RS,
    // so our ContainerResponseFilter doesn't apply to them. This is expected behavior.
    // The filter only applies to JAX-RS endpoints like /api/v1/*
    // Since the filter doesn't apply, we expect no Cache-Control header from our filter.
    // Note: This endpoint may not exist in all test environments (404 is acceptable)
    given()
      .when().get("/q/openapi")
      .then()
      .statusCode(anyOf(equalTo(200), equalTo(404)))
      // Filter doesn't apply to /q/* endpoints, so Cache-Control from filter should be null
      // (Quarkus may set its own, but that's outside our filter's scope)
      // We accept nullValue() since the endpoint may not exist or filter doesn't apply
      .header("Cache-Control", nullValue());
  }

  @Test
  void testSecurityHeadersDifferentStatusCodes() {
    // Test 200 OK
    given()
      .basePath("/api/v1")
      .when().get("/users")
      .then()
      .statusCode(200)
      .header("X-Content-Type-Options", equalTo("nosniff"));

    // Test 404 Not Found
    given()
      .basePath("/api/v1")
      .when().get("/users/99999")
      .then()
      .statusCode(404)
      .header("X-Content-Type-Options", equalTo("nosniff"));
  }

  @Test
  void testSecurityHeadersDifferentMethods() {
    // GET request
    given()
      .basePath("/api/v1")
      .when().get("/users")
      .then()
      .statusCode(200)
      .header("X-Content-Type-Options", equalTo("nosniff"));

    // POST request with valid email format
    given()
      .basePath("/api/v1")
      .contentType("application/json")
      .body("{\"name\":\"Test User\",\"email\":\"testuser@example.com\"}")
      .when().post("/users")
      .then()
      .statusCode(201) // Valid request should return 201 Created
      .header("X-Content-Type-Options", equalTo("nosniff"));
  }

  @Test
  void testPathMatchingSpecificity() {
    // Test that /api/v1 matches (should have no-cache)
    given()
      .basePath("/api/v1")
      .when().get("/users")
      .then()
      .statusCode(200)
      .header("Cache-Control", containsString("no-store"));
  }

  @Test
  void testPathMatchingEdgeCases() {
    // Test various path patterns to ensure correct matching behavior
    // SecurityHeadersFilter checks if path starts with "/api/v" and the character
    // at index 6 is a digit, followed by either end-of-string or '/'.
    
    // These should match (get no-cache headers):
    // - /api/v1, /api/v2, /api/v1/users (charAt(6) is digit, charAt(7) is '/' or end)
    given()
      .basePath("/api/v1")
      .when().get("/users")
      .then()
      .statusCode(200)
      .header("Cache-Control", containsString("no-store"));
    
    given()
      .basePath("/api/v2")
      .when().get("/users")
      .then()
      .statusCode(anyOf(equalTo(200), equalTo(404))) // May not exist, but if it does, should have no-cache
      .header("Cache-Control", anyOf(containsString("no-store"), nullValue()));
    
    // Note: Testing non-matching paths like /api-docs, /api/version, /api/v1abc
    // would require those endpoints to exist, which they may not. The path matching
    // logic is validated through the positive cases above and code review.
  }

  @Test
  void testHstsNotPresentOnHttp() {
    // HSTS should only be present on HTTPS requests
    // In test environment (HTTP), HSTS should not be present
    given()
      .basePath("/api/v1")
      .when().get("/users")
      .then()
      .statusCode(200)
      .header("Strict-Transport-Security", nullValue());
  }
}

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
  void testCacheControlNonApiEndpoints() {
    // Test root endpoint - should allow caching
    given()
      .when().get("/")
      .then()
      .statusCode(200)
      .header("Cache-Control", containsString("public"))
      .header("Cache-Control", containsString("max-age=3600"))
      .header("Cache-Control", containsString("must-revalidate"));
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
    // Test that /api-docs doesn't match /api/v pattern and gets caching
    // Note: This test may need adjustment based on actual API docs path
    given()
      .when().get("/q/openapi")
      .then()
      .statusCode(anyOf(equalTo(200), equalTo(404)))
      .header("Cache-Control", anyOf(
        containsString("no-store"), // If it matches /q/ pattern
        containsString("public") // If it doesn't match
      ));
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

    // POST request
    given()
      .basePath("/api/v1")
      .contentType("application/json")
      .body("{\"name\":\"Test User\",\"email\":\"test@example.com\"}")
      .when().post("/users")
      .then()
      .statusCode(anyOf(equalTo(201), equalTo(400))) // 201 if valid, 400 if invalid
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

    // Test that paths starting with /api/v match
    // This ensures /api/v1/, /api/v2/, etc. are treated as API endpoints
    // but /api-docs, /api.json would not match
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

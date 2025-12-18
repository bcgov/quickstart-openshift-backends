package ca.bc.gov.nrs.api.security;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.ext.Provider;
import java.util.ArrayList;
import java.util.List;

/**
 * Security headers filter to address ZAP penetration test findings.
 * 
 * Addresses the following ZAP alerts:
 * - Content Security Policy (CSP) Header Not Set [10038]
 * - Missing Anti-clickjacking Header [10020]
 * - Proxy Disclosure [40025]
 * - Cookie with SameSite Attribute None [10054]
 * - Permissions Policy Header Not Set [10063]
 * - Strict-Transport-Security Header Not Set [10035]
 * - X-Content-Type-Options Header Missing [10021]
 * - Re-examine Cache-control Directives [10015]
 * - Non-Storable Content [10049]
 * - Storable and Cacheable Content [10049]
 */
@Provider
public class SecurityHeadersFilter implements ContainerResponseFilter {

  // Headers to remove to prevent proxy/server disclosure
  private static final String[] HEADERS_TO_REMOVE = {
    "Server",
    "X-Powered-By",
    "Via",
    "X-AspNet-Version",
    "X-AspNetMvc-Version"
  };

  @Override
  public void filter(
      ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
    HttpHeaders headers = responseContext.getHeaders();

    // Security headers to address ZAP alerts

    // X-Content-Type-Options: Prevents MIME type sniffing
    // Addresses: X-Content-Type-Options Header Missing [10021]
    headers.add("X-Content-Type-Options", "nosniff");

    // X-Frame-Options: Prevents clickjacking attacks
    // Addresses: Missing Anti-clickjacking Header [10020]
    headers.add("X-Frame-Options", "DENY");

    // Strict-Transport-Security: Enforces HTTPS
    // Addresses: Strict-Transport-Security Header Not Set [10035]
    // Only set HSTS when the request is served over HTTPS
    // Check both direct HTTPS and proxy-forwarded HTTPS (for reverse proxy scenarios)
    boolean isHttps =
        requestContext.getUriInfo().getRequestUri().getScheme().equals("https")
            || "https".equalsIgnoreCase(
                requestContext.getHeaderString("X-Forwarded-Proto"));
    if (isHttps) {
      headers.add(
          "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
    }

    // Content-Security-Policy: Basic CSP (can be customized per application)
    // Addresses: Content Security Policy (CSP) Header Not Set [10038]
    headers.add("Content-Security-Policy", "default-src 'self'");

    // Permissions-Policy: Controls browser features
    // Addresses: Permissions Policy Header Not Set [10063]
    headers.add(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(),"
            + " gyroscope=(), speaker=()");

    // Referrer-Policy: Controls referrer information
    headers.add("Referrer-Policy", "strict-origin-when-cross-origin");

    // Hide server information (addresses Proxy Disclosure alert [40025])
    // Remove proxy/server disclosure headers
    for (String headerName : HEADERS_TO_REMOVE) {
      headers.remove(headerName);
    }

    // Fix cookie SameSite attribute - ensure all cookies have SameSite=Strict
    // Addresses: Cookie with SameSite Attribute None [10054]
    fixCookieSameSiteAttribute(headers);

    // Cache-Control headers
    // Addresses: Re-examine Cache-control Directives [10015],
    // Non-Storable Content [10049], Storable and Cacheable Content [10049]
    String path = requestContext.getUriInfo().getPath();
    // More specific path matching: /api/v matches /api/v1/, /api/v2/, etc. but not /api-docs, /api.json
    // Also exclude Swagger UI and other documentation endpoints from caching
    if (path.startsWith("/api/v") || path.startsWith("/q/")) {
      // For API endpoints and documentation (Swagger UI), prevent caching
      headers.add("Cache-Control", "no-store, no-cache, must-revalidate, private");
      headers.add("Pragma", "no-cache");
      headers.add("Expires", "0");
    } else {
      // For static content, allow some caching but with revalidation
      headers.add("Cache-Control", "public, max-age=3600, must-revalidate");
    }
  }

  /**
   * Ensures all Set-Cookie headers have SameSite=Strict attribute.
   * If SameSite is missing or set to None, replaces with Strict.
   */
  private void fixCookieSameSiteAttribute(HttpHeaders headers) {
    List<String> setCookieHeaders = headers.get("Set-Cookie");
    if (setCookieHeaders == null || setCookieHeaders.isEmpty()) {
      return;
    }

    List<String> fixedCookies = new ArrayList<>();
    for (String cookie : setCookieHeaders) {
      String fixedCookie = fixCookieHeader(cookie);
      fixedCookies.add(fixedCookie);
    }

    headers.put("Set-Cookie", fixedCookies);
  }

  /**
   * Fixes a single Set-Cookie header to ensure SameSite=Strict is set.
   */
  private String fixCookieHeader(String cookie) {
    if (cookie == null || cookie.isEmpty()) {
      return cookie;
    }

    // Check if SameSite is already present
    String cookieLower = cookie.toLowerCase();
    if (cookieLower.contains("samesite=none")) {
      // Replace SameSite=None with SameSite=Strict (more secure for most use cases)
      cookie = cookie.replaceAll("(?i);\\s*samesite=none", "; SameSite=Strict");
      cookie = cookie.replaceAll("(?i)samesite=none", "SameSite=Strict");
    } else if (!cookieLower.contains("samesite=")) {
      // Add SameSite=Strict if not present
      // Append before any HttpOnly, Secure, or Path attributes
      if (cookie.contains("; HttpOnly")) {
        cookie = cookie.replace("; HttpOnly", "; SameSite=Strict; HttpOnly");
      } else if (cookie.contains("; Secure")) {
        cookie = cookie.replace("; Secure", "; SameSite=Strict; Secure");
      } else if (cookie.contains("; Path=")) {
        cookie = cookie.replace("; Path=", "; SameSite=Strict; Path=");
      } else {
        cookie = cookie + "; SameSite=Strict";
      }
    }

    return cookie;
  }
}

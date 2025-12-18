package ca.bc.gov.nrs.api.security;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.MultivaluedMap;
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
    MultivaluedMap<String, Object> headers = responseContext.getHeaders();

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

    // Content-Security-Policy: Restrictive CSP for API endpoints
    // Addresses: Content Security Policy (CSP) Header Not Set [10038]
    // Note: This is a restrictive policy suitable for APIs. For web applications with
    // inline scripts/styles or external resources, customize this policy accordingly.
    headers.add("Content-Security-Policy", "default-src 'self'");

    // Permissions-Policy: Controls browser features
    // Addresses: Permissions Policy Header Not Set [10063]
    headers.add(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(),"
            + " gyroscope=(), speaker-selection=()");

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
    // More specific path matching: /api/v followed by digits matches /api/v1/, /api/v2/, etc.
    // but not /api-docs, /api.json, /api/version, /api/veterinary
    // Note: /q/* endpoints are handled by Quarkus's internal routing, not JAX-RS,
    // so this filter doesn't apply to them. The /q/ check is kept for completeness
    // but may not execute in practice.
    // Use startsWith() and character check instead of regex to avoid ReDoS vulnerability
    boolean isApiVersionPath = path.startsWith("/api/v") 
        && path.length() > 7 
        && Character.isDigit(path.charAt(7));
    if (isApiVersionPath || path.startsWith("/q/")) {
      // For API endpoints and documentation (Swagger UI), prevent caching
      // Use putSingle to replace any existing Cache-Control header
      headers.putSingle("Cache-Control", "no-store, no-cache, must-revalidate, private");
      headers.putSingle("Pragma", "no-cache");
      headers.putSingle("Expires", "0");
    } else {
      // For static content, allow some caching but with revalidation
      // Use putSingle to replace any existing Cache-Control header
      headers.putSingle("Cache-Control", "public, max-age=3600, must-revalidate");
    }
  }

  /**
   * Ensures all Set-Cookie headers have SameSite=Strict attribute.
   * If SameSite is missing or set to None, replaces with Strict.
   */
  @SuppressWarnings("unchecked")
  private void fixCookieSameSiteAttribute(MultivaluedMap<String, Object> headers) {
    List<Object> setCookieHeaders = headers.get("Set-Cookie");
    if (setCookieHeaders == null || setCookieHeaders.isEmpty()) {
      return;
    }

    List<Object> fixedCookies = new ArrayList<>();
    for (Object cookieObj : setCookieHeaders) {
      String cookie = cookieObj.toString();
      String fixedCookie = fixCookieHeader(cookie);
      fixedCookies.add(fixedCookie);
    }

    headers.put("Set-Cookie", fixedCookies);
  }

  /**
   * Fixes a single Set-Cookie header to ensure SameSite=Strict is set.
   * Handles existing SameSite values (None, Lax, Strict) to prevent duplicates.
   */
  private String fixCookieHeader(String cookie) {
    if (cookie == null || cookie.isEmpty()) {
      return cookie;
    }

    String cookieLower = cookie.toLowerCase();
    
    // Check if SameSite is already present with any value
    if (cookieLower.contains("samesite")) {
      // Early return if already Strict (no need to process)
      if (cookieLower.contains("samesite=strict") || cookieLower.contains("samesite = strict")) {
        return cookie;
      }
      // Replace any existing SameSite value with Strict
      // Handle both "; SameSite=None" and "SameSite=None" patterns, allowing spaces around '='
      cookie = cookie.replaceAll("(?i);\\s*samesite\\s*=\\s*(none|lax|strict)", "; SameSite=Strict");
      cookie = cookie.replaceAll("(?i)^samesite\\s*=\\s*(none|lax|strict)", "SameSite=Strict");
      return cookie;
    }
    
    // Add SameSite=Strict if not present
    // Insert before the earliest HttpOnly, Secure, or Path attribute (if any)
    int httpOnlyIndex = cookie.indexOf("; HttpOnly");
    int secureIndex = cookie.indexOf("; Secure");
    int pathIndex = cookie.indexOf("; Path=");
    
    int insertPos = -1;
    if (httpOnlyIndex != -1) {
      insertPos = httpOnlyIndex;
    }
    if (secureIndex != -1 && (insertPos == -1 || secureIndex < insertPos)) {
      insertPos = secureIndex;
    }
    if (pathIndex != -1 && (insertPos == -1 || pathIndex < insertPos)) {
      insertPos = pathIndex;
    }
    
    if (insertPos != -1) {
      // Insert before the first attribute found
      cookie = cookie.substring(0, insertPos) + "; SameSite=Strict" + cookie.substring(insertPos);
    } else {
      // No attributes found, append at the end
      cookie = cookie + "; SameSite=Strict";
    }

    return cookie;
  }
}

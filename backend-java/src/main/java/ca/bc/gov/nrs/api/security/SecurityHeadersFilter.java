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
    headers.putSingle("X-Content-Type-Options", "nosniff");

    // X-Frame-Options: Prevents clickjacking attacks
    // Addresses: Missing Anti-clickjacking Header [10020]
    headers.putSingle("X-Frame-Options", "DENY");

    // Strict-Transport-Security: Enforces HTTPS
    // Addresses: Strict-Transport-Security Header Not Set [10035]
    // Only set HSTS when the request is served over HTTPS
    // Check both direct HTTPS and proxy-forwarded HTTPS (for reverse proxy scenarios)
    // Check multiple common proxy headers to ensure HSTS is applied correctly
    String scheme = requestContext.getUriInfo().getRequestUri().getScheme();
    String xForwardedProto = requestContext.getHeaderString("X-Forwarded-Proto");
    String xForwardedScheme = requestContext.getHeaderString("X-Forwarded-Scheme");
    String xForwardedSsl = requestContext.getHeaderString("X-Forwarded-SSL");
    String frontEndHttps = requestContext.getHeaderString("Front-End-Https");
    boolean isHttps = "https".equals(scheme)
        || "https".equalsIgnoreCase(xForwardedProto)
        || "https".equalsIgnoreCase(xForwardedScheme)
        || "on".equalsIgnoreCase(xForwardedSsl)
        || "on".equalsIgnoreCase(frontEndHttps)
        || "true".equalsIgnoreCase(frontEndHttps);
    if (isHttps) {
      headers.putSingle(
          "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
    }

    // Content-Security-Policy: Restrictive CSP for API endpoints
    // Addresses: Content Security Policy (CSP) Header Not Set [10038]
    // Note: This is a restrictive policy suitable for APIs. For web applications with
    // inline scripts/styles or external resources, customize this policy accordingly.
    headers.putSingle("Content-Security-Policy", "default-src 'self'");

    // Permissions-Policy: Controls browser features
    // Addresses: Permissions Policy Header Not Set [10063]
    headers.putSingle(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(),"
            + "gyroscope=(), speaker-selection=()");

    // Referrer-Policy: Controls referrer information
    headers.putSingle("Referrer-Policy", "strict-origin-when-cross-origin");

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
    if (!path.startsWith("/")) {
      path = "/" + path;
    }
    boolean isApiVersionPath = isApiVersionPath(path);
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
   * If SameSite is missing or set to None or Lax, replaces with Strict.
   */
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
   * Package-private for testing purposes.
   */
  String fixCookieHeader(String cookie) {
    if (cookie == null || cookie.isEmpty()) {
      return cookie;
    }

    // Use string manipulation instead of regex to prevent ReDoS vulnerability
    // Split on ';' to examine individual attributes without using regex
    String[] parts = cookie.split(";", -1);  // -1 to preserve trailing empty strings
    boolean hasSameSite = false;
    boolean isAlreadyStrict = false;
    
    // First pass: check if SameSite exists and if it's already Strict
    for (String part : parts) {
      String trimmed = part.trim();
      if (trimmed.regionMatches(true, 0, "samesite", 0, "samesite".length())) {
        hasSameSite = true;
        int eqIndex = trimmed.indexOf('=');
        if (eqIndex != -1) {
          String value = trimmed.substring(eqIndex + 1).trim();
          if ("strict".equalsIgnoreCase(value)) {
            isAlreadyStrict = true;
            break;
          }
        }
      }
    }
    
    // Early return if already Strict (no need to process)
    if (hasSameSite && isAlreadyStrict) {
      return cookie;
    }
    
    // Second pass: rebuild cookie, normalizing all SameSite attributes to "SameSite=Strict"
    if (hasSameSite) {
      StringBuilder rebuilt = new StringBuilder();
      boolean first = true;
      for (String part : parts) {
        String trimmed = part.trim();
        if (trimmed.isEmpty()) {
          continue;  // Skip empty parts
        }
        if (trimmed.regionMatches(true, 0, "samesite", 0, "samesite".length())) {
          // Normalize any SameSite attribute to "SameSite=Strict"
          if (!first) {
            rebuilt.append("; ");
          }
          rebuilt.append("SameSite=Strict");
          first = false;
        } else {
          // Preserve non-SameSite attributes (including cookie name=value)
          if (!first) {
            rebuilt.append("; ");
          }
          rebuilt.append(trimmed);
          first = false;
        }
      }
      return rebuilt.toString();
    }
    
    // Add SameSite=Strict if not present
    // Insert before the earliest HttpOnly, Secure, or Path attribute (if any)
    // Cookie attributes are case-insensitive per RFC 6265
    String lowerCookie = cookie.toLowerCase();
    int httpOnlyIndex = lowerCookie.indexOf("; httponly");
    int secureIndex = lowerCookie.indexOf("; secure");
    int pathIndex = lowerCookie.indexOf("; path=");
    
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

  /**
   * Determines if a path matches the API version pattern (/api/v or /api/v followed by a digit).
   * Package-private for testing purposes.
   * 
   * More specific path matching: /api/v or /api/v followed by a digit matches /api/v1/, /api/v2/, etc.
   * but not /api-docs, /api.json, /api/version, /api/veterinary, /api/v1abc
   * 
   * @param path The request path to check
   * @return true if path matches API version pattern, false otherwise
   */
  boolean isApiVersionPath(String path) {
    // More specific path matching: /api/v or /api/v followed by a digit matches /api/v1/, /api/v2/, etc.
    // but not /api-docs, /api.json, /api/version, /api/veterinary, /api/v1abc
    // Note: /q/* endpoints are handled by Quarkus's internal routing, not JAX-RS,
    // so this filter doesn't apply to them. The /q/ check is kept for completeness
    // but may not execute in practice.
    // Use startsWith() and character check instead of regex to avoid ReDoS vulnerability
    // Check if path is exactly /api/v, or starts with /api/v followed by a digit
    // "/api/v" is 6 characters (indices 0-5), so index 6 is the first character after "/api/v"
    return path.equals("/api/v")
        || (path.startsWith("/api/v") 
            && path.length() >= 7  // At least "/api/v" (6 chars) + one digit
            && Character.isDigit(path.charAt(6))  // Character at index 6 (first char after "/api/v")
            && (path.length() == 7 || path.charAt(7) == '/'));  // Next char is end-of-string or '/'
  }
}

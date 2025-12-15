package ca.bc.gov.nrs.api.security;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;

/**
 * Security headers filter to address ZAP penetration test findings.
 * 
 * Addresses the following ZAP alerts:
 * - Content Security Policy (CSP) Header Not Set [10038]
 * - Missing Anti-clickjacking Header [10020]
 * - Proxy Disclosure [40025]
 * - Permissions Policy Header Not Set [10063]
 * - Strict-Transport-Security Header Not Set [10035]
 * - X-Content-Type-Options Header Missing [10021]
 * - Re-examine Cache-control Directives [10015]
 * - Non-Storable Content [10049]
 * - Storable and Cacheable Content [10049]
 */
@Provider
public class SecurityHeadersFilter implements ContainerResponseFilter {

  @Override
  public void filter(
      ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
    // Security headers to address ZAP alerts

    // X-Content-Type-Options: Prevents MIME type sniffing
    // Addresses: X-Content-Type-Options Header Missing [10021]
    responseContext.getHeaders().add("X-Content-Type-Options", "nosniff");

    // X-Frame-Options: Prevents clickjacking attacks
    // Addresses: Missing Anti-clickjacking Header [10020]
    responseContext.getHeaders().add("X-Frame-Options", "DENY");

    // Strict-Transport-Security: Enforces HTTPS
    // Addresses: Strict-Transport-Security Header Not Set [10035]
    responseContext
        .getHeaders()
        .add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

    // Content-Security-Policy: Basic CSP (can be customized per application)
    // Addresses: Content Security Policy (CSP) Header Not Set [10038]
    responseContext.getHeaders().add("Content-Security-Policy", "default-src 'self'");

    // Permissions-Policy: Controls browser features
    // Addresses: Permissions Policy Header Not Set [10063]
    responseContext
        .getHeaders()
        .add(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(),"
                + " gyroscope=(), speaker=()");

    // Referrer-Policy: Controls referrer information
    responseContext.getHeaders().add("Referrer-Policy", "strict-origin-when-cross-origin");

    // Hide server information (addresses Proxy Disclosure alert [40025])
    // Remove Server header if present
    responseContext.getHeaders().remove("Server");
    responseContext.getHeaders().remove("X-Powered-By");

    // Cache-Control headers
    // Addresses: Re-examine Cache-control Directives [10015],
    // Non-Storable Content [10049], Storable and Cacheable Content [10049]
    String path = requestContext.getUriInfo().getPath();
    if (path.startsWith("/api/")) {
      // For API endpoints, prevent caching
      responseContext
          .getHeaders()
          .add("Cache-Control", "no-store, no-cache, must-revalidate, private");
      responseContext.getHeaders().add("Pragma", "no-cache");
      responseContext.getHeaders().add("Expires", "0");
    } else {
      // For static content, allow some caching but with revalidation
      responseContext.getHeaders().add("Cache-Control", "public, max-age=3600, must-revalidate");
    }
  }
}

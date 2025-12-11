package ca.bc.gov.nrs.api;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.ext.Provider;

/**
 * Filter to add security headers to all HTTP responses.
 * Addresses ZAP scan findings for missing security headers.
 */
@Provider
public class SecurityHeadersFilter implements ContainerResponseFilter {

    private static final String CONTENT_SECURITY_POLICY = 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "font-src 'self' data:; " +
        "connect-src 'self'";
    
    private static final String X_FRAME_OPTIONS = "SAMEORIGIN";
    private static final String STRICT_TRANSPORT_SECURITY = "max-age=31536000; includeSubDomains; preload";
    private static final String X_CONTENT_TYPE_OPTIONS = "nosniff";
    private static final String PERMISSIONS_POLICY = 
        "geolocation=(), " +
        "microphone=(), " +
        "camera=(), " +
        "payment=(), " +
        "usb=(), " +
        "magnetometer=(), " +
        "gyroscope=(), " +
        "speaker=()";
    private static final String REFERRER_POLICY = "strict-origin-when-cross-origin";
    private static final String X_XSS_PROTECTION = "1; mode=block";

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        HttpHeaders headers = responseContext.getHeaders();
        
        // Content Security Policy - prevents XSS and injection attacks
        headers.add("Content-Security-Policy", CONTENT_SECURITY_POLICY);
        
        // X-Frame-Options - prevents clickjacking attacks
        headers.add("X-Frame-Options", X_FRAME_OPTIONS);
        
        // Strict-Transport-Security (HSTS) - enforces HTTPS
        headers.add("Strict-Transport-Security", STRICT_TRANSPORT_SECURITY);
        
        // X-Content-Type-Options - prevents MIME type sniffing
        headers.add("X-Content-Type-Options", X_CONTENT_TYPE_OPTIONS);
        
        // Permissions-Policy - controls browser features
        headers.add("Permissions-Policy", PERMISSIONS_POLICY);
        
        // Referrer-Policy - controls referrer information
        headers.add("Referrer-Policy", REFERRER_POLICY);
        
        // X-XSS-Protection - legacy but still useful for older browsers
        headers.add("X-XSS-Protection", X_XSS_PROTECTION);
        
        // Note: SameSite cookie attribute must be set when creating cookies
        // This is typically handled in the authentication/authorization layer
    }
}

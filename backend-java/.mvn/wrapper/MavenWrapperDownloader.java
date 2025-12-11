/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.stream.Collectors;

public final class MavenWrapperDownloader
{
    private static final String WRAPPER_VERSION = "3.2.0";

    private static final boolean VERBOSE = Boolean.parseBoolean( System.getenv( "MVNW_VERBOSE" ) );

    private static final java.util.Set<String> ALLOWED_MAVEN_REPO_HOSTS = java.util.Set.of(
        "repo.maven.apache.org",
        "repo1.maven.org"
    );

    // Pre-compute canonicalized allowed hosts for efficiency
    private static final java.util.Set<String> CANONICALIZED_ALLOWED_HOSTS = 
        ALLOWED_MAVEN_REPO_HOSTS.stream()
            .map(MavenWrapperDownloader::canonicalizeHost)
            .collect(Collectors.toSet());

    /**
     * Canonicalizes the hostname by removing any trailing dots and converting to lowercase.
     * Uses manual string operations instead of regex to avoid ReDoS vulnerabilities.
     * Returns null for null, empty, or invalid hostnames (e.g., all dots) for security.
     *
     * @param host the hostname to canonicalize
     * @return the canonicalized hostname, or null if host is null, empty, or invalid
     */
    private static String canonicalizeHost(String host) {
        if (host == null || host.isEmpty()) {
            return null;
        }
        // Remove trailing dots manually (more efficient than regex, avoids ReDoS)
        int endIndex = host.length();
        while (endIndex > 0 && host.charAt(endIndex - 1) == '.') {
            endIndex--;
        }
        // Check if hostname was all dots
        if (endIndex == 0) {
            return null; // hostname was all dots
        }
        // Convert to lowercase using ROOT locale for consistent behavior across all locales
        return host.substring(0, endIndex).toLowerCase(Locale.ROOT);
    }

    public static void main( String[] args )
    {
        log( "Apache Maven Wrapper Downloader " + WRAPPER_VERSION );

        if ( args.length != 2 )
        {
            System.err.println( " - ERROR wrapperUrl or wrapperJarPath parameter missing" );
            System.exit( 1 );
        }

        try
        {
            log( " - Downloader started" );
            final URL wrapperUrl = new URL( args[0] );
            // SSRF protection: validate URL before downloading
            if (!isAllowedUrl(wrapperUrl))
            {
                System.err.println(" - ERROR: Only downloads from " + ALLOWED_MAVEN_REPO_HOSTS + " over HTTPS are allowed.");
                System.exit(1);
            }
            // Path traversal protection: validate path is within base directory
            final String jarPath = args[1];
            final Path baseDir = Paths.get("").toAbsolutePath().normalize();
            final Path wrapperJarPath = baseDir.resolve(jarPath).normalize();
            // Check that the path is within the base directory.
            if (!wrapperJarPath.startsWith(baseDir)) {
                System.err.println(" - ERROR: Provided JAR path escapes working directory.");
                System.exit(1);
            }
            // Defense-in-depth: resolve symlinks in parent directories
            Path parentDir = wrapperJarPath.getParent();
            if (parentDir != null) {
                Files.createDirectories(parentDir);
                if (!parentDir.toRealPath().startsWith(baseDir.toRealPath())) {
                    System.err.println(" - ERROR: Path resolves outside working directory.");
                    System.exit(1);
                }
            }
            downloadFileFromURL( wrapperUrl, wrapperJarPath );
            log( "Done" );
        }
        catch ( IOException e )
        {
            System.err.println( "- Error downloading: " + e.getMessage() );
            if ( VERBOSE )
            {
                e.printStackTrace();
            }
            System.exit( 1 );
        }
    }

    /**
     * Validates that the given URL is allowed for downloading Maven wrapper.
     * Only HTTPS protocol is allowed and the host must exactly match (after canonicalization)
     * one of the allowed Maven repository hosts. This prevents SSRF attacks by:
     * - Requiring exact host match (no subdomains)
     * - Canonicalizing hostnames (removing trailing dots, normalizing case)
     * - Restricting to HTTPS only
     * - Rejecting null, empty, or invalid hostnames
     * - Rejecting URLs with user info (user:pass@host)
     *
     * @param url the URL to validate
     * @return true if the URL is allowed, false otherwise
     */
    private static boolean isAllowedUrl( URL url )
    {
        // Only allow HTTPS protocol
        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            return false;
        }
        
        // Reject URLs with user info (user:pass@host) - SSRF protection
        if (url.getUserInfo() != null && !url.getUserInfo().isEmpty()) {
            return false;
        }
        
        String actualHost = canonicalizeHost(url.getHost());
        // Reject null or invalid hostnames
        if (actualHost == null) {
            return false;
        }
        
        // No subdomain allowed, just exact host match using pre-computed canonicalized hosts.
        // IP addresses and localhost are automatically rejected since they won't match allowed hostnames.
        return CANONICALIZED_ALLOWED_HOSTS.contains(actualHost);
    }

    private static void downloadFileFromURL( URL wrapperUrl, Path wrapperJarPath )
        throws IOException
    {
        log( " - Downloading to: " + wrapperJarPath );
        if ( System.getenv( "MVNW_USERNAME" ) != null && System.getenv( "MVNW_PASSWORD" ) != null )
        {
            final String username = System.getenv( "MVNW_USERNAME" );
            final char[] password = System.getenv( "MVNW_PASSWORD" ).toCharArray();
            Authenticator.setDefault( new Authenticator()
            {
                @Override
                protected PasswordAuthentication getPasswordAuthentication()
                {
                    return new PasswordAuthentication( username, password );
                }
            } );
        }
        try ( InputStream inStream = wrapperUrl.openStream() )
        {
            Files.copy( inStream, wrapperJarPath, StandardCopyOption.REPLACE_EXISTING );
        }
        log( " - Downloader complete" );
    }

    private static void log( String msg )
    {
        if ( VERBOSE )
        {
            System.out.println( msg );
        }
    }

}

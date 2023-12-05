package com.springaddon.SpringAddon;

import com.c4_soft.springaddons.security.oidc.starter.properties.OpenidProviderProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.springaddon.SpringAddon.config.SecurityConfig;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class DynamicTenantsAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {
    private final Set<String> issuerBaseUris;
    private final Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter;
    private final Map<String, JwtAuthenticationProvider> jwtManagers = new ConcurrentHashMap<>();
    private final JwtIssuerAuthenticationManagerResolver delegate = new JwtIssuerAuthenticationManagerResolver(this::getAuthenticationManager);

    public DynamicTenantsAuthenticationManagerResolver(
            SpringAddonsOidcProperties addonsProperties,
            Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {
        this.issuerBaseUris = Stream.of(addonsProperties.getOps()).map(OpenidProviderProperties::getIss).map(SecurityConfig::baseUri).map(URI::toString)
                .collect(Collectors.toSet());
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
    }

    @Override
    public AuthenticationManager resolve(HttpServletRequest context) {
        return delegate.resolve(context);
    }

    public AuthenticationManager getAuthenticationManager(String issuerUriString) {
        final var issuerBaseUri = SecurityConfig.baseUri(URI.create(issuerUriString)).toString();
        if (!issuerBaseUris.contains(issuerBaseUri)) {
            throw new InvalidIssuerException(issuerUriString);
        }
        if (!this.jwtManagers.containsKey(issuerUriString)) {
            this.jwtManagers.put(issuerUriString, getProvider(issuerUriString));
        }
        return jwtManagers.get(issuerUriString)::authenticate;
    }

    private JwtAuthenticationProvider getProvider(String issuerUriString) {
        var provider = new JwtAuthenticationProvider(JwtDecoders.fromIssuerLocation(issuerUriString));
        provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
        return provider;
    }
}
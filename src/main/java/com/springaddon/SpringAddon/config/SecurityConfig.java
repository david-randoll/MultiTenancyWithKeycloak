package com.springaddon.SpringAddon.config;

import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.JwtAbstractAuthenticationTokenConverter;
import com.springaddon.SpringAddon.DynamicTenantProperties;
import com.springaddon.SpringAddon.InvalidIssuerException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Map;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    JwtAbstractAuthenticationTokenConverter authenticationConverter(
            Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
            DynamicTenantProperties addonsProperties) {
        return jwt -> {
            final var issProperties = addonsProperties.getOpProperties(jwt.getClaims().get(JwtClaimNames.ISS).toString());
            return new OAuthentication<>(
                    new OpenidClaimSet(jwt.getClaims(), issProperties.getUsernameClaim()),
                    authoritiesConverter.convert(jwt.getClaims()),
                    jwt.getTokenValue()
            );
        };
    }

    public static URI baseUri(URI uri) {
        if (uri == null) {
            return null;
        }
        try {
            return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), null, null, null);
        } catch (URISyntaxException e) {
            throw new InvalidIssuerException(uri.toString());
        }
    }
}
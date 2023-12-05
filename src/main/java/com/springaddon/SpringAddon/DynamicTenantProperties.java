package com.springaddon.SpringAddon;

import com.c4_soft.springaddons.security.oidc.starter.properties.MissingAuthorizationServerConfigurationException;
import com.c4_soft.springaddons.security.oidc.starter.properties.OpenidProviderProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.springaddon.SpringAddon.config.SecurityConfig;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.net.URI;

@Primary
@Component
public class DynamicTenantProperties extends SpringAddonsOidcProperties {

    @Override
    public OpenidProviderProperties getOpProperties(String issOrJwks) throws MissingAuthorizationServerConfigurationException {
        return super.getOpProperties(SecurityConfig.baseUri(URI.create(issOrJwks)).toString());
    }
}
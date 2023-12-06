package com.springaddon.SpringAddon.controller;

import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/protected")
public class ProtectedController {
    @GetMapping
    @PreAuthorize("hasAuthority('super-admin')")
    public String hello() {
        return "Dear %s, glad to see you!".formatted(SecurityContextHolder.getContext().getAuthentication().getName());
    }

    @GetMapping("/greet")
    public String greet(OAuthentication<OpenidClaimSet> who) {
        var id = who.getClaims().getSubject();
        var username = who.getClaims().getPreferredUsername();
        var email = who.getClaims().getEmail();
        var name = who.getClaims().getName();
        var title = who.getClaims().getClaim("title");


        return String.format(
                "Hello %s! You are granted with %s.",
                who.getClaims().getName(),
                who.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }
}
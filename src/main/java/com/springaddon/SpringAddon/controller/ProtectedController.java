package com.springaddon.SpringAddon.controller;

import org.springframework.security.access.prepost.PreAuthorize;
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
}
package com.springaddon.SpringAddon;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.UNAUTHORIZED)
public class InvalidIssuerException extends RuntimeException {
    private static final long serialVersionUID = 4431133205219303797L;

    public InvalidIssuerException(String issuerUriString) {
        super("Issuer %s is not trusted".formatted(issuerUriString));
    }
}
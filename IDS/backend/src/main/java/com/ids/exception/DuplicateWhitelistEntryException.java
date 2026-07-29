package com.ids.exception;

/** Thrown when an IP is added to my_whitelist that is already present. */
public class DuplicateWhitelistEntryException extends RuntimeException {
    public DuplicateWhitelistEntryException(String message) {
        super(message);
    }
}

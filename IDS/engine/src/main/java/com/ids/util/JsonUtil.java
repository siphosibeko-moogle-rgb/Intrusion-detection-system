package com.ids.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonUtil {

    private static final ObjectMapper mapper = new ObjectMapper();

    // Convert object → JSON string
    public static String toJson(Object obj) {
        try {
            return mapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            System.err.println("[JsonUtil] Failed to serialize object: " + e.getMessage());
            return "{}";
        }
    }

    // Convert JSON string → object
    public static <T> T fromJson(String json, Class<T> clazz) {
        try {
            return mapper.readValue(json, clazz);
        } catch (Exception e) {
            System.err.println("[JsonUtil] Failed to deserialize JSON: " + e.getMessage());
            return null;
        }
    }
}
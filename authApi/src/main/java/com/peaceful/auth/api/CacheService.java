package com.peaceful.auth.api;

/**
 * Created by WangJun on 14-4-20.
 */
public interface CacheService {

    void put(String key, Object value, Integer expire);

    Object get(String key);

    void clear(String key);

    void clearAll();
}

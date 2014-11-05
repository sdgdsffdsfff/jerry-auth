package com.peaceful.auth.config;


import com.alibaba.fastjson.JSON;
import com.peaceful.auth.Impl.AuthServiceImpl;
import com.peaceful.auth.api.AuthService;
import com.peaceful.auth.data.domain.JSONRole;
import com.peaceful.auth.exception.CreateSessionException;
import com.peaceful.util.StringUtils;
import com.peaceful.util.Util;
import com.peaceful.web.util.Http;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;


/**
 * Created by liuweiwei on 14-10-14.
 */
public class AuthConfigInterceptor extends HandlerInterceptorAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthConfigInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }
        if (StringUtils.isEmpty(Http.getCurrentUser()))
            return true;
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        AUTH.Function function = handlerMethod.getMethodAnnotation(AUTH.Function.class);
        AUTH.Role role = handlerMethod.getMethodAnnotation(AUTH.Role.class);
        if (function == null && role == null) {
            return true;
        }
        String[] functionKeys = (function == null ? null : function.key());
        String[] roleKeys = (role == null ? null : role.key());
        if (checkFunction(Http.getCurrentUser(), functionKeys) || checkRole(Http.getCurrentUser(), roleKeys)) {
            return true;
        } else {
            Util.report("--------------------------访问禁止----------------------------------");
            try {
                response.setContentType("application/json");
                PrintWriter writer = response.getWriter();
                writer.write("{\"code\":403,\"result\":\"访问禁止\"}");
                writer.flush();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return false;
        }
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {

        super.postHandle(request, response, handler, modelAndView);
    }

    private static boolean checkFunction(String email, String[] keys) {
        if (keys == null || keys.length == 0)
            return false;
        AuthService authService ;
        try {
            authService = AuthServiceImpl.getAuthService();
        } catch (CreateSessionException e) {
            LOGGER.error("checkFunction:{}", e);
            return false;
        }
        for (int i = 0; i < keys.length; i++) {
            if (authService.getMenu(keys[i], email) != null) {
                return true;
            }
        }
        return false;
    }

    private static boolean checkRole(String email, String[] keys) {
        if (keys == null || keys.length == 0)
            return false;
        AuthService authService ;
        try {
            authService = AuthServiceImpl.getAuthService();
        } catch (CreateSessionException e) {
            LOGGER.error("checkFunction:{}", e);
            return false;
        }
        List<JSONRole> roleList = authService.getUser(email).roles;
        if (roleList == null || roleList.size() == 0)
            return false;
        for (int i = 0; i < keys.length; i++) {
            for (int n = 0; n < roleList.size(); n++) {
                if (roleList.get(n).getName().equals(keys[i]))
                    return true;
            }
        }
        return false;
    }
}


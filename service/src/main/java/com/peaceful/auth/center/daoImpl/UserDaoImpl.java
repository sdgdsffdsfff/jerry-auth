package com.peaceful.auth.center.daoImpl;

import com.peaceful.auth.center.domain.*;
import com.peaceful.auth.center.dao.UserDao;
import com.peaceful.util.Util;
import org.hibernate.SessionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.*;


/**
 * Created by wangjun on 14-4-15.
 */
@Component(value = "userDao")
public class UserDaoImpl implements UserDao {

    private Logger logger = LoggerFactory.getLogger(this.getClass());
    @Autowired
    @Qualifier("sessionFactory")
    SessionFactory sessionFactory = null;

    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    public UserDaoImpl() {

    }


    public DJUser findUserByUserId(Integer id) {
        DJUser user = (DJUser) sessionFactory.getCurrentSession().get(DJUser.class, id);
        Util.report("eager load roles :" + user.roles.size());
        if (user.system != null) {
            logger.info("load system id is {}", user.system.id);
        }
        return user;
    }


    public DJUser findUserByUserName(String name, Integer systemId) {
        List result = sessionFactory.getCurrentSession().createQuery("from user where email = ? and system.id = ?").setString(0, name).setInteger(1, systemId).list();
        if (result != null && result.size() > 0) {
            return (DJUser) result.get(0);
        }
        return null;
    }

    @Override
    public DJUser findUserByUserNameAndPassword(String name, Integer systemId,String password) {
        List result = sessionFactory.getCurrentSession().createQuery("from user where email = ? and system.id = ? and password = ?").setString(0, name).setInteger(1, systemId).setString(2,password).list();
        if (result != null && result.size() > 0) {
            return (DJUser) result.get(0);
        }
        return null;
    }

    public List<DJResource> findCanAccessResourcesOfUserOfSystem(Integer uid, Integer systemId) {
        Set<DJResource> result = new HashSet<DJResource>();
        List<DJResource> resourceList = new ArrayList<DJResource>();
        DJUser user = findUserByUserId(uid);
        if (user == null || user.isdel != 1) {
            return resourceList;
        }
        Collection<DJRole> liveRoles = sessionFactory.getCurrentSession().createFilter(
                user.roles,
                ("where this.isdel = 1 and this.system.id = ?")
        ).setInteger(0, systemId).list();

        for (DJRole role : liveRoles) {
            Collection<DJResource> resources = sessionFactory.getCurrentSession().createFilter(
                    role.resources,
                    ("where this.isdel = 1")
            ).list();
            for (DJResource resource : resources) {
                result.add(resource);
            }
        }
        for (DJResource resource : result) {
            resourceList.add(resource);
        }
        return resourceList;
    }

    public List<DJMenu> findCanAccessMenusOfUserOfSystem(Integer id, Integer systemId) {
        Set<DJMenu> result = new HashSet<DJMenu>();
        List<DJMenu> menuList = new ArrayList<DJMenu>();
        DJUser user = findUserByUserId(id);
        if (user == null || user.isdel != 1) {
            return menuList;
        }
        Collection<DJRole> liveRoles = sessionFactory.getCurrentSession().createFilter(
                user.roles,
                ("where this.isdel = 1 and this.system.id = ?")
        ).setInteger(0, systemId).list();

        for (DJRole role : liveRoles) {
            Collection<DJMenu> resources = sessionFactory.getCurrentSession().createFilter(
                    role.menus,
                    ("where this.isdel = 1")
            ).list();
            for (DJMenu menu : resources) {
                result.add(menu);
            }
        }
        for (DJMenu menu : result) {
            menuList.add(menu);
        }
        return menuList;
    }

    public List<DJRole> findNowRolesOfUserOfSystem(Integer id, Integer systemId) {
        DJUser user = findUserByUserId(id);
        Collection<DJRole> liveRoles = sessionFactory.getCurrentSession().createFilter(
                user.roles,
                ("where this.isdel = 1 and this.system.id = ?")
        ).setInteger(0, systemId).list();
        return (List<DJRole>) liveRoles;
    }

    public void insert(DJUser user) {
        sessionFactory.getCurrentSession().save(user);
    }

    public void update(DJUser user) {
        sessionFactory.getCurrentSession().update(user);
    }

}

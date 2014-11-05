package com.peaceful.auth.center.ServiceImpl;

import com.peaceful.auth.center.Service.SystemService;
import com.peaceful.auth.center.dao.SystemDao;
import com.peaceful.auth.center.domain.DJMenu;
import com.peaceful.auth.center.domain.DJRole;
import com.peaceful.auth.center.domain.DJSystem;
import com.peaceful.auth.util.HibernateSystemUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Created by wangjun on 14-4-17.
 */
@Component(value = "systemService")
public class SystemServiceImpl implements SystemService {

    private Logger logger = LoggerFactory.getLogger(this.getClass());
    @Autowired
    SystemDao systemDao = null;

    public void setSystemDao(SystemDao systemDao) {
        this.systemDao = systemDao;
    }

    public DJSystem findSystemByName(String name) {
        return systemDao.findSystemByName(name);
    }

    @Override
    public boolean systemIsExist(Integer systemId) {
        return systemDao.findSystemById(systemId) == null ? false : true;
    }

    public List<DJSystem> findRolesSortBySystem() {
        List<DJSystem> djSystems = systemDao.findAllSystems();
        HibernateSystemUtil.systemLoad(djSystems, HibernateSystemUtil.ROLE);
        return djSystems;
    }

    public List<DJRole> findRolesBySystemId(Integer systemId) {
        DJSystem system = systemDao.findSystemById(systemId);
        HibernateSystemUtil.load(system, HibernateSystemUtil.ROLE);
        if (system == null || system.roles == null)
            return null;
        Set<DJRole> roles = system.roles;
        List<DJRole> roleList = new ArrayList<DJRole>();
        for (DJRole role : roles) {
            roleList.add(role);
        }
        return roleList;
    }


    @Override
    public List<DJMenu> findMenusBySystemId(Integer systemId) {
        Set<DJMenu> menus = systemDao.findSystemById(systemId).menus;
        List<DJMenu> result = new ArrayList<DJMenu>();
        for (DJMenu menu : menus) {
            logger.info("load parent menu {}", menu.parentMenu == null ? null : menu.parentMenu.id);
            result.add(menu);
        }
        return result;
    }


    public DJSystem findLiveSystemBySystemId(Integer systemId) {
        return systemDao.findLiveSystemById(systemId);
    }

    public List<DJSystem> findUsersSortBySystem() {
        List<DJSystem> djSystems = systemDao.findAllSystems();
        HibernateSystemUtil.systemLoad(djSystems, HibernateSystemUtil.USER);
        return djSystems;
    }

    public List<DJSystem> findResourcesSortBySystem() {

        List<DJSystem> djSystems = systemDao.findAllSystems();
        HibernateSystemUtil.systemLoad(djSystems, HibernateSystemUtil.RESOURCE);
        return djSystems;
    }

    public List<DJSystem> findMenusSortBySystem() {

        List<DJSystem> djSystems = systemDao.findAllSystems();
        HibernateSystemUtil.systemLoad(djSystems, HibernateSystemUtil.MENU);
        return djSystems;
    }


    public List<DJSystem> findAllSystems() {
        return systemDao.findAllSystems();
    }

    public void insertSystem(DJSystem system) {
        systemDao.inserte(system);
    }

    public DJSystem findSystemBySystemId(Integer systemId) {
        return systemDao.findSystemById(systemId);
    }

    public DJSystem findSystemBySystemId(Integer systemId, Integer loadType) {
        DJSystem system = systemDao.findLiveSystemById(systemId);
        if (loadType == HibernateSystemUtil.ROLE) {
            logger.info("load roles {}", system.roles);
        } else if (loadType == HibernateSystemUtil.ROLEANDUSER) {
            logger.info("load roles {} and users", system.roles.size(), system.roles.iterator().hasNext());
        } else if (loadType == HibernateSystemUtil.MENUANDPARENT) {
            logger.info("load menus size {}", system.menus.size());
            if (system.menus != null) {
                for (DJMenu menu : system.menus) {
                    logger.info("load menu {}", menu.parentMenu);
                }
            }
        } else if (loadType == HibernateSystemUtil.MENU) {
            logger.info("load menus size {}", system.menus.size());
        } else if (loadType == HibernateSystemUtil.USER) {
            logger.info("load users size {}", system.users.size());
        } else if (loadType == HibernateSystemUtil.RESOURCE) {
            logger.info("load users size {}", system.resources.size());
        }

        return system;
    }

    public void updateSystem(DJSystem system) {
        systemDao.update(system);
    }


}

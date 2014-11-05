package com.peaceful.auth.center.Service;

import com.peaceful.auth.center.domain.DJMenu;
import com.peaceful.auth.center.domain.DJRole;
import com.peaceful.auth.center.domain.DJSystem;

import java.util.List;

/**
 * Created by wangjun on 14-4-17.
 */
public interface SystemService {

    abstract DJSystem findSystemByName(String name);

    boolean systemIsExist(Integer systemId);

    List<DJSystem> findRolesSortBySystem();


    List<DJRole> findRolesBySystemId(Integer systemId);

    /**
     * 所有的menu，并级联其父对象
     *
     * @param systemId
     * @return
     */
    List<DJMenu> findMenusBySystemId(Integer systemId);

    DJSystem findLiveSystemBySystemId(Integer systemId);

    List<DJSystem> findUsersSortBySystem();

    List<DJSystem> findResourcesSortBySystem();

    List<DJSystem> findMenusSortBySystem();


    List<DJSystem> findAllSystems();

    void insertSystem(DJSystem system);

    DJSystem findSystemBySystemId(Integer systemId);

    DJSystem findSystemBySystemId(Integer systemId, Integer loadType);

    void updateSystem(DJSystem system);
}

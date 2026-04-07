package com.logistics.authentication.application.port.out;

import java.util.List;

import com.logistics.authentication.domain.readmodel.RoleUserCount;

public interface UserRoleStatsQueryPort {

	List<RoleUserCount> countUsersGroupedByRole();
}

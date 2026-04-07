package com.logistics.authentication.application.port.in;

import java.util.List;

import com.logistics.authentication.domain.readmodel.RoleUserCount;

public interface GetUserRoleStatsUseCase {

	List<RoleUserCount> getUsersByRole();
}

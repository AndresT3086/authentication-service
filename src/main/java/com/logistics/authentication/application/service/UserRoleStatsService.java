package com.logistics.authentication.application.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.logistics.authentication.application.port.in.GetUserRoleStatsUseCase;
import com.logistics.authentication.application.port.out.UserRoleStatsQueryPort;
import com.logistics.authentication.domain.readmodel.RoleUserCount;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserRoleStatsService implements GetUserRoleStatsUseCase {

	private final UserRoleStatsQueryPort userRoleStatsQueryPort;

	@Override
	public List<RoleUserCount> getUsersByRole() {
		return userRoleStatsQueryPort.countUsersGroupedByRole();
	}
}

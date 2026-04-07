package com.logistics.authentication.infrastructure.adapter.out.persistence;

import java.util.List;

import org.springframework.stereotype.Component;

import com.logistics.authentication.application.port.out.UserRoleStatsQueryPort;
import com.logistics.authentication.domain.readmodel.RoleUserCount;
import com.logistics.authentication.infrastructure.adapter.out.persistence.repository.UserJpaRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class UserRoleStatsAdapter implements UserRoleStatsQueryPort {

	private final UserJpaRepository userJpaRepository;

	@Override
	public List<RoleUserCount> countUsersGroupedByRole() {
		return userJpaRepository.countUsersGroupedByRole().stream()
				.map(row -> new RoleUserCount((String) row[0], ((Number) row[1]).longValue()))
				.toList();
	}
}

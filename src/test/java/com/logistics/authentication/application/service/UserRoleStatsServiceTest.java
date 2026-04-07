package com.logistics.authentication.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.logistics.authentication.application.port.out.UserRoleStatsQueryPort;
import com.logistics.authentication.domain.readmodel.RoleUserCount;

@ExtendWith(MockitoExtension.class)
class UserRoleStatsServiceTest {

	@Mock
	private UserRoleStatsQueryPort userRoleStatsQueryPort;

	@InjectMocks
	private UserRoleStatsService userRoleStatsService;

	@Test
	void delegatesToPort() {
		when(userRoleStatsQueryPort.countUsersGroupedByRole())
				.thenReturn(List.of(new RoleUserCount("ROLE_ADMIN", 1L)));

		var result = userRoleStatsService.getUsersByRole();

		assertThat(result).hasSize(1);
		assertThat(result.get(0).roleName()).isEqualTo("ROLE_ADMIN");
		assertThat(result.get(0).userCount()).isEqualTo(1L);
	}
}

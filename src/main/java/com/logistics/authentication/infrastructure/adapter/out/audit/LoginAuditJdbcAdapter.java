package com.logistics.authentication.infrastructure.adapter.out.audit;

import java.sql.Types;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import com.logistics.authentication.application.port.out.LoginAuditPort;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class LoginAuditJdbcAdapter implements LoginAuditPort {

	private final JdbcTemplate jdbcTemplate;

	@Override
	public void recordLoginAttempt(UUID userIdOrNull, String email, boolean success, String reasonOrNull) {
		jdbcTemplate.update(connection -> {
			var ps = connection.prepareStatement("CALL sp_log_login_event(?, ?, ?, ?)");
			if (userIdOrNull == null) {
				ps.setNull(1, Types.OTHER);
			}
			else {
				ps.setObject(1, userIdOrNull);
			}
			ps.setString(2, email);
			ps.setBoolean(3, success);
			if (reasonOrNull == null) {
				ps.setNull(4, Types.VARCHAR);
			}
			else {
				ps.setString(4, reasonOrNull);
			}
			return ps;
		});
	}
}

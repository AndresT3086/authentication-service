package com.logistics.authentication.infrastructure.adapter.in.web.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Agregación: cantidad de usuarios por rol (consulta join + group by)")
public record UserRoleStatsResponseBody(
		@Schema(description = "Filas agregadas por nombre de rol") List<RoleUserCountItem> rows) {

	@Schema(description = "Una fila del reporte")
	public record RoleUserCountItem(
			@Schema(example = "ROLE_ADMIN") String roleName,
			@Schema(example = "1") long userCount) {
	}
}

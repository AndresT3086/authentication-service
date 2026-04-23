package com.logistics.authentication.infrastructure.adapter.in.web;

import org.springframework.hateoas.EntityModel;
import org.springframework.hateoas.Link;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.logistics.authentication.application.port.in.GetUserRoleStatsUseCase;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.UserRoleStatsResponseBody;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.UserRoleStatsResponseBody.RoleUserCountItem;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/admin/stats")
@RequiredArgsConstructor
@Tag(name = "Administración", description = "Estadísticas protegidas por rol ADMIN")
@PreAuthorize("hasRole('ADMIN')")
public class AdminStatsController {

	private final GetUserRoleStatsUseCase getUserRoleStatsUseCase;

	@Operation(
			summary = "Usuarios por rol",
			description = "Consulta agregada (join + group by). Requiere JWT con ROLE_ADMIN.",
			security = @SecurityRequirement(name = "bearer-jwt"))
	@GetMapping(value = "/users-by-role", produces = { MediaType.APPLICATION_JSON_VALUE, "application/hal+json" })
	public ResponseEntity<EntityModel<UserRoleStatsResponseBody>> usersByRole(HttpServletRequest request) {
		var rows = getUserRoleStatsUseCase.getUsersByRole().stream()
				.map(r -> new RoleUserCountItem(r.roleName(), r.userCount()))
				.toList();
		var body = new UserRoleStatsResponseBody(rows);
		EntityModel<UserRoleStatsResponseBody> model = EntityModel.of(body);
		String docsHref = ServletUriComponentsBuilder.fromRequestUri(request)
				.replacePath("/swagger-ui/index.html")
				.replaceQuery(null)
				.build()
				.toUriString();
		model.add(Link.of(docsHref, "describedby"));
		return ResponseEntity.ok(model);
	}
}

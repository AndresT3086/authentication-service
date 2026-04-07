package com.logistics.authentication.infrastructure.adapter.out.persistence.entity;

import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "auth_roles")
@Getter
@Setter
public class RoleEntity {

	@Id
	private UUID id;

	@Column(nullable = false, unique = true, length = 64)
	private String name;
}

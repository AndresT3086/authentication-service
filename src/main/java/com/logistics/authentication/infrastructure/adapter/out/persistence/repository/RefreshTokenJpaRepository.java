package com.logistics.authentication.infrastructure.adapter.out.persistence.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.RefreshTokenEntity;

public interface RefreshTokenJpaRepository extends JpaRepository<RefreshTokenEntity, UUID> {

	@Query("select r from RefreshTokenEntity r where r.tokenHash = :hash and r.revoked = false and r.expiresAt > :now")
	Optional<RefreshTokenEntity> findActiveByHash(@Param("hash") String hash, @Param("now") Instant now);

	@Modifying(clearAutomatically = true)
	@Transactional
	@Query("update RefreshTokenEntity r set r.revoked = true where r.userId = :userId and r.revoked = false")
	int revokeAllActiveByUserId(@Param("userId") UUID userId);
}

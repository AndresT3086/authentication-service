package com.logistics.authentication.infrastructure.adapter.out.persistence.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "auth_refresh_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshTokenEntity {

    @Id
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "token_hash", nullable = false, length = 64, unique = true)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean revoked;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public static RefreshTokenEntity create(
            UUID id,
            UUID userId,
            String tokenHash,
            Instant expiresAt,
            Instant createdAt
    ) {
        RefreshTokenEntity e = new RefreshTokenEntity();
        e.id = id;
        e.userId = userId;
        e.tokenHash = tokenHash;
        e.expiresAt = expiresAt;
        e.revoked = false;
        e.createdAt = createdAt;
        return e;
    }

    public void revoke() {
        this.revoked = true;
    }
}
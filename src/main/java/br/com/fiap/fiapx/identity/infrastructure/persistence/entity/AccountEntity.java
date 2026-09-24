package br.com.fiap.fiapx.identity.infrastructure.persistence.entity;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;
@Entity @Table(name="accounts")
public class AccountEntity {
    @Id public UUID id;
    @Column(nullable=false,length=100) public String name;
    @Column(nullable=false,unique=true,length=254) public String email;
    @Column(name="password_hash",nullable=false,length=100) public String passwordHash;
    @Column(nullable=false,length=16) public String role;
    @Column(nullable=false) public boolean active;
    @Column(name="credential_version",nullable=false) public long credentialVersion;
    @Column(name="created_at",nullable=false,updatable=false) public Instant createdAt;
    public AccountEntity() {}
}

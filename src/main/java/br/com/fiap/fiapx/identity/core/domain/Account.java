package br.com.fiap.fiapx.identity.core.domain;
import java.util.*;
import java.time.Instant;
public record Account(UUID id, String name, String email, String passwordHash, Role role,
                      boolean active, long credentialVersion, Instant createdAt) {
    public enum Role { USER, ADMIN }
    public Account {
        Objects.requireNonNull(id); Objects.requireNonNull(role); Objects.requireNonNull(createdAt);
        name = validName(name); email = normalizeEmail(email);
        if (passwordHash == null || passwordHash.isBlank() || credentialVersion < 0) throw new IllegalArgumentException("Invalid account");
    }
    public static String validName(String name) {
        if (name == null || name.isBlank() || name.strip().length() > 100) throw new IllegalArgumentException("Invalid name");
        return name.strip();
    }
    public static String normalizeEmail(String email) {
        if (email == null) throw new IllegalArgumentException("Invalid email");
        String result = email.strip().toLowerCase(Locale.ROOT);
        if (result.length() > 254 || !result.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+")) throw new IllegalArgumentException("Invalid email");
        return result;
    }
    public Account profile(String newName) { return new Account(id,newName,email,passwordHash,role,active,credentialVersion,createdAt); }
    public Account credentials(String newEmail, String hash) { return new Account(id,name,newEmail,hash,role,active,credentialVersion+1,createdAt); }
    public Account permissions(Role newRole, boolean enabled) {
        return new Account(id,name,email,passwordHash,newRole,enabled,credentialVersion+(active != enabled ? 1 : 0),createdAt);
    }
    @Override public String toString() { return "Account[id=" + id + ", role=" + role + ", active=" + active + "]"; }
}

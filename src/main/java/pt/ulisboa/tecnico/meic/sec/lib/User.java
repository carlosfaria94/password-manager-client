package pt.ulisboa.tecnico.meic.sec.lib;

import java.util.HashSet;
import java.util.Set;

public class User {
    private int id;
    private String fingerprint;
    private String publicKey;
    private String signature;
    private Set<Password> passwords = new HashSet<>();

    public User(String publicKey) {
        this.publicKey = publicKey;
    }

    public User(String publicKey, String signature) {
        this.publicKey = publicKey;
        this.signature = signature;
    }

    public User(int id, String fingerprint, Set<Password> passwords) {
        this.id = id;
        this.fingerprint = fingerprint;
        this.passwords = passwords;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public Set<Password> getPasswords() {
        return passwords;
    }

    public void setPasswords(Set<Password> passwords) {
        this.passwords = passwords;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", fingerprint='" + fingerprint + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", passwords=" + passwords +
                '}';
    }
}

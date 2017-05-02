package pt.ulisboa.tecnico.meic.sec.lib;

import java.util.UUID;

public class LocalPassword implements Comparable {

    private final String username;
    private final String password;
    private final int version;
    private String domain;
    private UUID deviceId;

    public LocalPassword(String domain, String username, String password, String version, String deviceId) {
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.version = Integer.valueOf(version);
        this.deviceId = UUID.fromString(deviceId);
    }

    public String getDomain() {
        return domain;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public int getVersion() {
        return version;
    }

    public UUID getDeviceId() {
        return deviceId;
    }

    @Override
    public int compareTo(Object o) {
        if (o instanceof LocalPassword) {
            LocalPassword other = (LocalPassword) o;
            int comparison = other.getVersion() - version;
            if (comparison == 0) {
                return other.getDeviceId().compareTo(this.deviceId);
            } else return comparison;
        } else throw new RuntimeException("Not LocalPassword");
    }

    @Override
    public String toString() {
        return "LocalPassword{" +
                "domain='" + domain + '\'' +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", version=" + version + '\'' +
                ", deviceId=" + deviceId +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        LocalPassword that = (LocalPassword) o;

        if (getVersion() != that.getVersion()) return false;
        if (getDomain() != null ? !getDomain().equals(that.getDomain()) : that.getDomain() != null) return false;
        if (getUsername() != null ? !getUsername().equals(that.getUsername()) : that.getUsername() != null)
            return false;
        return getPassword() != null ? getPassword().equals(that.getPassword()) : that.getPassword() == null;
    }

}

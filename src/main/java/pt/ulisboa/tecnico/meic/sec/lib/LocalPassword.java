package pt.ulisboa.tecnico.meic.sec.lib;

/**
 * Created by francisco on 10/04/2017.
 */
public class LocalPassword implements Comparable{

    private String domain;
    private final String username;
    private final String password;
    private final int version;

    public LocalPassword(String domain, String username, String password, String version) {

        this.domain = domain;
        this.username = username;
        this.password = password;
        this.version = Integer.valueOf(version);
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

    @Override
    public int compareTo(Object o) {
        if(o instanceof LocalPassword)
            return ((LocalPassword)o).getVersion() - version;
        else throw new RuntimeException("Not LocalPassword");
    }

    @Override
    public String toString() {
        return "LocalPassword{" +
                "domain='" + domain + '\'' +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", version=" + version +
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

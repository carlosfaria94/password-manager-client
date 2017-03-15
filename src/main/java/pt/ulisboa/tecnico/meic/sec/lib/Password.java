package pt.ulisboa.tecnico.meic.sec.lib;

public class Password {

    private String publicKey;
    private String domain;
    private String username;
    private String password;
    private String pwdSignature;
    private String timestamp;
    private String nonce;
    private String reqSignature;

    public Password(String publicKey, String domain, String username, String password, String pwdSignature, String timestamp, String nonce, String reqSignature) {
        this.publicKey = publicKey;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.pwdSignature = pwdSignature;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }

    public Password(String publicKey, String domain, String username, String pwdSignature, String timestamp, String nonce, String reqSignature) {
        this.publicKey = publicKey;
        this.domain = domain;
        this.username = username;
        this.pwdSignature = pwdSignature;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }

    public String getPublicKey() {
        return publicKey;
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

    public String getPwdSignature() {
        return pwdSignature;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getNonce() {
        return nonce;
    }

    public String getReqSignature() {
        return reqSignature;
    }

    @Override
    public String toString() {
        return "Password{" +
                "publicKey='" + publicKey + '\'' +
                ", domain='" + domain + '\'' +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", pwdSignature='" + pwdSignature + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", nonce='" + nonce + '\'' +
                ", reqSignature='" + reqSignature + '\'' +
                '}';
    }
}

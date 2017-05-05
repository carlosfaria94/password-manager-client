package pt.ulisboa.tecnico.meic.sec.lib;

public class IV {
    public String publicKey;
    public String hash;
    public String value;
    public String timestamp;
    public String nonce;
    public String reqSignature;

    public IV(String publicKey, String hash, String value, String timestamp, String nonce, String reqSignature) {
        this.publicKey = publicKey;
        this.hash = hash;
        this.value = value;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }
    public IV(String publicKey, String hash, String timestamp, String nonce, String reqSignature) {
        this.publicKey = publicKey;
        this.hash = hash;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getReqSignature() {
        return reqSignature;
    }

    public void setReqSignature(String reqSignature) {
        this.reqSignature = reqSignature;
    }

    @Override
    public String toString() {
        return "IV{" +
                "hash='" + hash + '\'' +
                ", value='" + value + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", nonce='" + nonce + '\'' +
                ", reqSignature='" + reqSignature + '\'' +
                '}';
    }
}

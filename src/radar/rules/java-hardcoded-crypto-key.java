import javax.crypto.spec.SecretKeySpec;

class Bad {
    // ruleid: java-hardcoded-crypto-key
    void bad() {
        new SecretKeySpec("hardcoded-secret-key".getBytes(), "AES");
    }

    // ok: java-hardcoded-crypto-key
    void good(byte[] keyBytes) {
        new SecretKeySpec(keyBytes, "AES");
    }
}

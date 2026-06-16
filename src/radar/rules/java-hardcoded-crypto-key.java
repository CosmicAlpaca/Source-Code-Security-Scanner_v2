import javax.crypto.spec.SecretKeySpec;

class TestHardcodedCryptoKey {
    void bad() {
        // ruleid: java-hardcoded-crypto-key
        new SecretKeySpec("hardcoded-secret-key".getBytes(), "AES");
    }

    void good(byte[] keyBytes) {
        // ok: java-hardcoded-crypto-key
        new SecretKeySpec(keyBytes, "AES");
    }
}

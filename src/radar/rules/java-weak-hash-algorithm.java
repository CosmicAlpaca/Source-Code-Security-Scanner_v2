import java.security.MessageDigest;

class TestWeakHash {
    void bad() throws Exception {
        // ruleid: java-weak-hash-algorithm
        MessageDigest.getInstance("MD5");
    }

    void bad2() throws Exception {
        // ruleid: java-weak-hash-algorithm
        MessageDigest.getInstance("SHA-1");
    }

    void good() throws Exception {
        // ok: java-weak-hash-algorithm
        MessageDigest.getInstance("SHA-256");
    }
}

import java.security.MessageDigest;

class Bad {
    // ruleid: java-weak-hash-algorithm
    void bad() throws Exception {
        MessageDigest.getInstance("MD5");
    }

    // ruleid: java-weak-hash-algorithm
    void bad2() throws Exception {
        MessageDigest.getInstance("SHA-1");
    }

    // ok: java-weak-hash-algorithm
    void good() throws Exception {
        MessageDigest.getInstance("SHA-256");
    }
}

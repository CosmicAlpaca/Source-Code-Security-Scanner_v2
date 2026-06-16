import java.io.*;

class TestDeser {
    void bad(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        // ruleid: java-unsafe-deserialization
        ois.readObject();
    }
}

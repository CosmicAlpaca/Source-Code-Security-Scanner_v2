import java.io.*;

class Bad {
    // ruleid: java-unsafe-deserialization
    void bad(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        Object obj = ois.readObject();
    }
}

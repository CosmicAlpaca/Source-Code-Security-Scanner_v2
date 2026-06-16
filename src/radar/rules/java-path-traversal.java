import java.io.*;
import javax.servlet.http.HttpServletRequest;

class Bad {
    // ruleid: java-path-traversal
    void bad(HttpServletRequest req) throws IOException {
        String name = req.getParameter("file");
        new FileInputStream("/uploads/" + name);
    }

    // ok: java-path-traversal
    void good() throws IOException {
        new FileInputStream("/uploads/known-file.txt");
    }
}

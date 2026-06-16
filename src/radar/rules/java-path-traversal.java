import java.io.*;
import javax.servlet.http.HttpServletRequest;

class TestPathTraversal {
    void bad(HttpServletRequest req) throws IOException {
        String name = req.getParameter("file");
        // ruleid: java-path-traversal
        new FileInputStream("/uploads/" + name);
    }

    void good() throws IOException {
        // ok: java-path-traversal
        new FileInputStream("/uploads/known-file.txt");
    }
}

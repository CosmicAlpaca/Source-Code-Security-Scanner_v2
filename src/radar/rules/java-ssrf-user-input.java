import java.net.*;
import javax.servlet.http.HttpServletRequest;

class Bad {
    void bad(HttpServletRequest req) throws Exception {
        String target = req.getParameter("url");
        new URL(target).openConnection(); // ruleid: java-ssrf-user-input
    }

    void good() throws Exception {
        new URL("https://trusted-api.example.com/data").openConnection(); // ok: java-ssrf-user-input
    }
}

import java.net.*;
import javax.servlet.http.HttpServletRequest;

class Bad {
    // ruleid: java-ssrf-user-input
    void bad(HttpServletRequest req) throws Exception {
        String target = req.getParameter("url");
        new URL(target).openConnection();
    }
}

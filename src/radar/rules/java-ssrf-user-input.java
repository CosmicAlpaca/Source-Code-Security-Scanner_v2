import java.net.*;
import javax.servlet.http.HttpServletRequest;

class TestSsrf {
    void bad(HttpServletRequest req) throws Exception {
        String target = req.getParameter("url");
        // ruleid: java-ssrf-user-input
        new URL(target).openConnection();
    }

    void good() throws Exception {
        String trusted = "https://internal-api.local/data";
        // ok: java-ssrf-user-input
        new URL(trusted).openConnection();
    }
}

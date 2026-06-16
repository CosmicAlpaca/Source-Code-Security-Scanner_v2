import javax.servlet.http.HttpServletRequest;

class TestCmdInjection {
    void bad(HttpServletRequest req) throws Exception {
        String file = req.getParameter("file");
        // ruleid: java-command-injection
        Runtime.getRuntime().exec("cat " + file);
    }

    void good() throws Exception {
        // ok: java-command-injection
        Runtime.getRuntime().exec(new String[]{"ls", "-la"});
    }
}

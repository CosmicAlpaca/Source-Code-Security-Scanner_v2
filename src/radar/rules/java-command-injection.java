import javax.servlet.http.HttpServletRequest;

class Bad {
    // ruleid: java-command-injection
    void bad(HttpServletRequest req) throws Exception {
        String file = req.getParameter("file");
        Runtime.getRuntime().exec("cat " + file);
    }
}

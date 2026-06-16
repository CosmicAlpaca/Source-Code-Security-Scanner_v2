import javax.servlet.http.*;

class TestOpenRedirect {
    void bad(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String url = req.getParameter("next");
        // ruleid: java-open-redirect
        resp.sendRedirect(url);
    }

    void good(HttpServletResponse resp) throws Exception {
        // ok: java-open-redirect
        resp.sendRedirect("/dashboard");
    }
}

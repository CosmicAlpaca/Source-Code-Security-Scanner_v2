import javax.servlet.http.*;

class Bad {
    // ruleid: java-open-redirect
    void bad(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String url = req.getParameter("next");
        resp.sendRedirect(url);
    }

    // ok: java-open-redirect
    void good(HttpServletResponse resp) throws Exception {
        resp.sendRedirect("/dashboard");
    }
}

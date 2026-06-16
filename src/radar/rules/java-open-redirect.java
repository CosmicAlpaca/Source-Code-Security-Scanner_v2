import javax.servlet.http.*;

class Bad {
    void bad(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String url = req.getParameter("next");
        resp.sendRedirect(url); // ruleid: java-open-redirect
    }

    void good(HttpServletResponse resp) throws Exception {
        resp.sendRedirect("/dashboard"); // ok: java-open-redirect
    }
}

import java.sql.*;

class Bad {
    // ruleid: java-sql-string-concat
    void bad(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT * FROM users WHERE id = '" + userId + "'");
    }

    // ok: java-sql-string-concat
    void good(Connection conn, String userId) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
        ps.executeQuery();
    }
}

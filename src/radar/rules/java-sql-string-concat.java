import java.sql.*;

class TestSqlConcat {
    void bad(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        // ruleid: java-sql-string-concat
        stmt.execute("SELECT * FROM users WHERE id = '" + userId + "'");
    }

    void good(Connection conn, String userId) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
        // ok: java-sql-string-concat
        ps.executeQuery();
    }
}

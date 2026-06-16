import java.sql.DriverManager;

class TestHardcodedPassword {
    void bad() throws Exception {
        // ruleid: java-hardcoded-password
        DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "password123");
    }

    void good() throws Exception {
        String pwd = System.getenv("DB_PASSWORD");
        // ok: java-hardcoded-password
        DriverManager.getConnection("jdbc:mysql://localhost/db", "root", pwd);
    }
}

import java.sql.DriverManager;

class Bad {
    // ruleid: java-hardcoded-password
    String password = "super_secret_123";

    // ruleid: java-hardcoded-password
    void bad() throws Exception {
        DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "password123");
    }

    // ok: java-hardcoded-password
    void good() throws Exception {
        String pwd = System.getenv("DB_PASSWORD");
        DriverManager.getConnection("jdbc:mysql://localhost/db", "root", pwd);
    }
}

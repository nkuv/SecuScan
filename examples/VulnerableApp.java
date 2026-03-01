import java.sql.*;
import java.io.*;
import java.util.Scanner;
import javax.servlet.http.*;

/**
 * Intentionally vulnerable Java application for SecuScan demo.
 * DO NOT USE IN PRODUCTION.
 */
public class VulnerableApp {

    // 1. Hardcoded credentials (CRITICAL)
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk-1234567890abcdef1234567890abcdef";

    // 2. SQL Injection
    public static String getUser(String username) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        // BAD: direct string concatenation - SQL injection
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return rs.getString("email");
    }

    // 3. Safe version (parameterized query) for comparison
    public static String getUserSafe(String username) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
        stmt.setString(1, username);
        ResultSet rs = stmt.executeQuery();
        return rs.getString("email");
    }

    // 4. Command Injection
    public static void runCommand(String userInput) throws Exception {
        // BAD: user input passed directly to Runtime.exec
        Runtime.getRuntime().exec("ls " + userInput);
    }

    // 5. Path Traversal
    public static String readFile(String filename) throws Exception {
        // BAD: no path sanitization - allows "../../../etc/passwd"
        FileReader reader = new FileReader("/app/files/" + filename);
        BufferedReader br = new BufferedReader(reader);
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) sb.append(line);
        return sb.toString();
    }

    // 6. XSS - reflected (relevant if output goes to HTTP response)
    public static String buildHtml(String userInput) {
        // BAD: user input reflected without encoding
        return "<html><body>Hello " + userInput + "</body></html>";
    }

    // 7. Insecure Deserialization
    public static Object deserialize(byte[] data) throws Exception {
        // BAD: deserializing untrusted data
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // 8. Weak random (not cryptographically secure)
    public static int generateToken() {
        // BAD: should use SecureRandom
        return new java.util.Random().nextInt(1000000);
    }

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        // Using vulnerable method
        System.out.println(getUser(username));

        System.out.print("Enter filename: ");
        String filename = scanner.nextLine();
        System.out.println(readFile(filename));
    }
}

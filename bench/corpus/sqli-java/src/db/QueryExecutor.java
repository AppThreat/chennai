package db;

import java.sql.*;

public class QueryExecutor {
    private Connection conn;

    public QueryExecutor(Connection conn) {
        this.conn = conn;
    }

    /**
     * Search users by name. Vulnerable: user input is concatenated directly
     * into the SQL string without parameterization.
     */
    public ResultSet searchUsers(String query) throws SQLException {
        String sql = "SELECT id, name, email FROM users WHERE name LIKE '%"
                   + query + "%'";
        Statement stmt = conn.createStatement();  // line 42
        return stmt.executeQuery(sql);
    }

    public void safeSearch(String query) throws SQLException {
        // This version uses parameterized queries (not vulnerable).
        String sql = "SELECT id, name, email FROM users WHERE name LIKE ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, "%" + query + "%");
        ps.executeQuery();
    }
}

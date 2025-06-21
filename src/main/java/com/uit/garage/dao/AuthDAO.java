package com.uit.garage.dao;

import com.uit.garage.model.User;
import com.uit.garage.model.Role;
import com.uit.garage.util.DBUtil;
import java.sql.*;

public class AuthDAO {
    // Kiểm tra đăng nhập
    public User authenticate(String username, String password) throws SQLException {
        String sql = "SELECT * FROM users WHERE username = ?";
        
        try (Connection conn = DBUtil.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                String storedHash = rs.getString("password");
                if (PasswordUtil.checkPassword(password, storedHash)) {
                    return new User(
                        rs.getInt("id"),
                        rs.getString("username"),
                        storedHash,
                        Role.valueOf(rs.getString("role"))
                    );
                }
            }
            return null; // Sai username/password
        }
    }
}

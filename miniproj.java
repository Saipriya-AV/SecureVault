import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.sql.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;


public class miniproj {
    private static final Font MMT = new Font("Montserrat", Font.BOLD, 18);
    private static final String JDBC_URL = "jdbc:mysql://localhost:3306/mydatabase";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static String lginusrname;

    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            csiGUI();
        });
    }

    private static void csiGUI() {
        JFrame frm = new JFrame("User Authentication");
        frm.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        JPanel pnl = new JPanel();
        pnl.setLayout(new GridLayout(4, 2, 10, 10));
        pnl.setBackground(new Color(3, 12, 23));
        pnl.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10)); // Add margin

        sfc(pnl, MMT);

        pnl.add(new JLabel());
        JLabel hlbl = csl("SecureVault", 24);
        hlbl.setForeground(new Color(241, 183, 58));
        hlbl.setHorizontalAlignment(JLabel.CENTER); // Center the heading
        JLabel ulbl = new JLabel("Username:");
        ulbl.setForeground(new Color(241, 183, 58));
        ulbl.setFont(MMT);
        JTextField ufld = new JTextField();
        sfc(ufld, MMT);

        JLabel pwlbl = new JLabel("Password:");
        pwlbl.setForeground(new Color(241, 183, 58));
        pwlbl.setFont(MMT);

        JPasswordField pfld = new JPasswordField();
        sfc(pfld, MMT);


        JButton lgbtn = csb("Login", MMT);
        lgbtn.addActionListener(e -> {
            String unme = ufld.getText();
            String password = new String(pfld.getPassword());

            if (authur(unme, password)) {
                lginusrname = unme;
                frm.dispose();
                cslGUI();
            } else {
                JOptionPane.showMessageDialog(frm, "Incorrect password. Please try again.");
            }
        });


        JLabel rglbl = new JLabel("Not registered? Click here to register.");
        rglbl.setForeground(new Color(241, 183, 58));
        rglbl.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        rglbl.setFont(MMT);


        frm.getContentPane().add(pnl, BorderLayout.CENTER);

        pnl.add(hlbl);
        pnl.add(ulbl);
        pnl.add(ufld);
        pnl.add(pwlbl);
        pnl.add(pfld);
        pnl.add(lgbtn);
        pnl.add(rglbl);


        frm.setSize(500, 300);
        frm.setLocationRelativeTo(null);
        frm.setVisible(true);


        rglbl.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                csrGUI(frm);
            }
        });
    }


    private static JButton csb(String text, Font font) {
        JButton bt = new JButton(text);
        bt.setBackground(new Color(241, 183, 58));
        bt.setForeground(new Color(3, 12, 23));
        bt.setBorder(BorderFactory.createLineBorder(new Color(241, 183, 58)));
        bt.setMargin(new Insets(10, 10, 10, 10));
        bt.setFont(font);
        return bt;
    }

    private static JLabel csl(String text, int fontSize) {
        JLabel lbl = new JLabel(text);
        lbl.setForeground(new Color(241, 183, 58));
        lbl.setFont(MMT.deriveFont(Font.PLAIN, fontSize));
        return lbl;
    }

    private static JFileChooser cfc() {
        JFileChooser fchoose = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        fchoose.setDialogTitle("Select a File");
        sfc(fchoose, MMT);
        return fchoose;
    }

    private static void sfc(Component component, Font font) {
        component.setFont(font);
    }
    private static void csrGUI(JFrame previousFrame) {
        JFrame rfrm = new JFrame("User Registration");
        rfrm.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel rpnl = new JPanel();
        rpnl.setLayout(new GridLayout(5, 2, 10, 10));
        rpnl.setBackground(new Color(3, 12, 23));
        rpnl.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Set font for the panel
        sfc(rpnl, MMT);

        JLabel ulbl = new JLabel("Username:");
        ulbl.setForeground(new Color(241, 183, 58));
        ulbl.setFont(MMT);
        JTextField ufld = new JTextField();
        sfc(ufld, MMT);

        JLabel plbl = new JLabel("Password:");
        plbl.setForeground(new Color(241, 183, 58));
        plbl.setFont(MMT);
        JPasswordField pfld = new JPasswordField();
        sfc(pfld, MMT);

        JButton regbtn = csb("Register", MMT);

        // Add a "Go Back" button
        JButton gbbtn = csb("Go Back", MMT);
        gbbtn.addActionListener(e -> {
            rfrm.dispose();
            previousFrame.setVisible(true);
        });

        rpnl.add(ulbl);
        rpnl.add(ufld);
        rpnl.add(plbl);
        rpnl.add(pfld);
        rpnl.add(regbtn);
        rpnl.add(gbbtn);

        rfrm.getContentPane().add(rpnl, BorderLayout.CENTER);

        rfrm.setSize(500, 300);
        rfrm.setLocationRelativeTo(null);
        rfrm.setVisible(true);

        regbtn.addActionListener(e -> {
            String unme = ufld.getText();
            String password = new String(pfld.getPassword());

            // Validate input fields
            if (unme.trim().isEmpty() || password.trim().isEmpty()) {
                JOptionPane.showMessageDialog(rfrm, "Please fill in all fields.");
                return;
            }

            if (!uexs(unme)) {
                cusr(unme, password);
                JOptionPane.showMessageDialog(rfrm, "User registered successfully!");
                rfrm.dispose();
                previousFrame.setVisible(true);
            } else {
                JOptionPane.showMessageDialog(rfrm, "User already exists. Please log in.");
            }
        });
    }



    private static void cslGUI() {
        JFrame lgfrm = new JFrame("Welcome, " + lginusrname + "!");
        lgfrm.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel lgpnl = new JPanel();
        lgpnl.setLayout(new GridLayout(6, 1, 10, 10));
        lgpnl.setBackground(new Color(3, 12, 23));
        lgpnl.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        sfc(lgpnl, MMT);

        JButton selectFilebt = csb("Select and Encrypt File", MMT);
        JButton decrfbt = csb("Decrypt and View File", MMT);
        JButton viewFilesbt = csb("View Encrypted Files", MMT);
        JButton chpwdbt = csb("Change Password", MMT);
        JButton exitbt = csb("Exit", MMT);

        lgpnl.add(csl("Welcome, " + lginusrname + "!", 20));
        lgpnl.add(selectFilebt);
        lgpnl.add(decrfbt);
        lgpnl.add(viewFilesbt);
        lgpnl.add(chpwdbt);
        lgpnl.add(exitbt);

        lgfrm.getContentPane().add(lgpnl, BorderLayout.CENTER);
        lgfrm.setSize(500, 300);
        lgfrm.setLocationRelativeTo(null);
        lgfrm.setVisible(true);

        selectFilebt.addActionListener(e -> {
            JFileChooser fchoose = cfc();
            int result = fchoose.showOpenDialog(lgfrm);

            if (result == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fchoose.getSelectedFile();
                String encrky = JOptionPane.showInputDialog(lgfrm, "Enter the encryption key:");

                if (encrky != null && !encrky.isEmpty()) {
                    encrf(selectedFile, encrky);
                    JOptionPane.showMessageDialog(lgfrm, "File encrypted successfully!");
                } else {
                    JOptionPane.showMessageDialog(lgfrm, "Encryption key is required.");
                }
            }
        });

        decrfbt.addActionListener(e -> {
            JFileChooser fchoose = new JFileChooser();
            int result = fchoose.showOpenDialog(lgfrm);

            if (result == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fchoose.getSelectedFile();
                String decryptionKey = JOptionPane.showInputDialog(lgfrm, "Enter the decryption key:");

                if (decryptionKey != null && !decryptionKey.isEmpty()) {
                    if (decrf(selectedFile, decryptionKey)) {
                        JOptionPane.showMessageDialog(lgfrm, "File decrypted successfully! You can view the file.");
                    } else {
                        JOptionPane.showMessageDialog(lgfrm, "Decryption failed. Incorrect key or file format.");
                    }
                } else {
                    JOptionPane.showMessageDialog(lgfrm, "Decryption key is required.");
                }
            }
        });

        viewFilesbt.addActionListener(e -> venf());
        exitbt.addActionListener(e -> System.exit(0));
        chpwdbt.addActionListener(e -> chpwd());
        exitbt.addActionListener(e -> System.exit(0));
    }
    private static void chpwd() {
        JPasswordField oldpswdf = new JPasswordField();
        JPasswordField newpswdf = new JPasswordField();
        JPasswordField confirmnewpswdf = new JPasswordField();

        Object[] message = {
                "Old Password:", oldpswdf,
                "New Password:", newpswdf,
                "Confirm New Password:", confirmnewpswdf
        };

        int option = JOptionPane.showConfirmDialog(null, message, "Change Password", JOptionPane.OK_CANCEL_OPTION);

        if (option == JOptionPane.OK_OPTION) {
            String oldPassword = new String(oldpswdf.getPassword());
            String newPassword = new String(newpswdf.getPassword());
            String confirmNewPassword = new String(confirmnewpswdf.getPassword());

            if (vpswd(oldPassword)) {
                if (newPassword.equals(confirmNewPassword)) {
                    if (chpwdb(newPassword)) {
                        JOptionPane.showMessageDialog(null, "Password changed successfully!");
                    } else {
                        JOptionPane.showMessageDialog(null, "Failed to change password. Please try again.");
                    }
                } else {
                    JOptionPane.showMessageDialog(null, "New passwords do not match.");
                }
            } else {
                JOptionPane.showMessageDialog(null, "Incorrect old password. Unable to change password.");
            }
        }
    }
    private static JButton csb(String text) {
        JButton bt = new JButton(text);
        bt.setBackground(new Color(241, 183, 58));
        bt.setForeground(new Color(3, 12, 23));
        bt.setMargin(new Insets(10, 10, 10, 10));
        return bt;
    }



    private static boolean chpwdb(String newPassword) {
        String query = "UPDATE usr SET upwd = ? WHERE uname = ?";
        try (Connection connection = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASSWORD);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {

            preparedStatement.setString(1, newPassword);
            preparedStatement.setString(2, lginusrname);

            int rowsUpdated = preparedStatement.executeUpdate();
            return rowsUpdated > 0;
        } catch (SQLException ex) {
            ex.printStackTrace();
            return false;
        }
    }
    private static boolean vpswd(String password) {
        String query = "SELECT * FROM usr WHERE uname = ? AND upwd = ?";
        try (Connection connection = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASSWORD);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {

            preparedStatement.setString(1, lginusrname);
            preparedStatement.setString(2, password);

            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                return resultSet.next();
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
            return false;
        }
    }
    private static void venf() {
        JPasswordField passwordField = new JPasswordField();
        Object[] message = {"Enter your password:", passwordField};

        int option = JOptionPane.showConfirmDialog(null, message, "Password Verification", JOptionPane.OK_CANCEL_OPTION);

        if (option == JOptionPane.OK_OPTION) {
            String enteredPassword = new String(passwordField.getPassword());

            if (vpswd(enteredPassword)) {
                String query = "SELECT fname, enkey FROM encryfls WHERE uname = ?";
                try (Connection connection = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASSWORD);
                     PreparedStatement preparedStatement = connection.prepareStatement(query)) {

                    preparedStatement.setString(1, lginusrname);

                    try (ResultSet resultSet = preparedStatement.executeQuery()) {
                        StringBuilder filesList = new StringBuilder("List of Encrypted Files:\n");

                        while (resultSet.next()) {
                            String fname = resultSet.getString("fname");
                            String encrky = resultSet.getString("enkey");
                            filesList.append(fname).append(" - ").append(encrky).append("\n");
                        }

                        JOptionPane.showMessageDialog(null, filesList.toString());
                    }
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            } else {
                JOptionPane.showMessageDialog(null, "Incorrect password. Unable to view encrypted files.");
            }
        }
    }

    private static boolean authur(String unme, String password) {
        String query = "SELECT * FROM usr WHERE uname = ? AND upwd = ?";
        try (Connection connection = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASSWORD);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {

            preparedStatement.setString(1, unme);
            preparedStatement.setString(2, password);

            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                return resultSet.next();
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    private static boolean uexs(String unme) {
        String query = "SELECT * FROM usr WHERE uname = ?";
        try (Connection connection = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASSWORD);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {

            preparedStatement.setString(1, unme);

            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                return resultSet.next();
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    private static void cusr(String unme, String password) {
        String query = "INSERT INTO usr (uname, upwd) VALUES (?, ?)";
        try (Connection connection = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASSWORD);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {

            preparedStatement.setString(1, unme);
            preparedStatement.setString(2, password);
            preparedStatement.executeUpdate();
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    private static void encrf(File fileToEncrypt, String userDefinedKey) {
        try {
            byte[] fileBytes = Files.readAllBytes(fileToEncrypt.toPath());

            // Use SHA-256 as a key derivation function
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = Arrays.copyOf(userDefinedKey.getBytes(StandardCharsets.UTF_8), 32);

            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(fileBytes);

            Files.write(fileToEncrypt.toPath(), encryptedBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            // Store filename and encryption key in MySQL
            sfinfo(fileToEncrypt.getName(),userDefinedKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean decrf(File fileToDecrypt, String userDefinedKey) {
        try {
            byte[] keyBytes = Arrays.copyOf(userDefinedKey.getBytes(StandardCharsets.UTF_8), 32);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] encryptedBytes = Files.readAllBytes(fileToDecrypt.toPath());
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            Files.write(fileToDecrypt.toPath(), decryptedBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    private static void sfinfo(String fname, String encrky) {
        String query = "INSERT INTO encryfls (uname, fname, enkey) VALUES (?, ?, ?)";
        try (Connection connection = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASSWORD);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {

            preparedStatement.setString(1, lginusrname);
            preparedStatement.setString(2, fname);
            preparedStatement.setString(3, encrky);
            preparedStatement.executeUpdate();
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }
}
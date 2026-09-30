import java.sql.*;
import javax.servlet.http.*;
import javax.xml.parsers.DocumentBuilderFactory;
import java.security.MessageDigest;

@RestController
public class UserController {
    @GetMapping("/user")
    public String user(@RequestParam String id, HttpServletResponse response) throws Exception {
        String q = "SELECT * FROM users WHERE id = " + id;
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery(q);
        return "ok";
    }
    @GetMapping("/safe")
    public String safe(@RequestParam String id) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        return "ok";
    }
    public void servlet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        resp.getWriter().println("<p>Hello " + name + "</p>");
        Runtime.getRuntime().exec("ping " + req.getParameter("host"));
        new java.io.File("/data/" + req.getParameter("f")).delete();
        javax.naming.InitialContext ctx = new javax.naming.InitialContext();
        ctx.lookup(req.getParameter("jndi"));
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        MessageDigest md = MessageDigest.getInstance("MD5");
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
        resp.sendRedirect(req.getParameter("next"));
    }
}

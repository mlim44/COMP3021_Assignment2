import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class VulnerableApp {
    public static void main(String[] args) throws Exception {
        int port = 8000;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        System.out.println("VulnerableApp running on http://localhost:" + port);

        server.createContext("/xss", new XssHandler());
        server.createContext("/sql", new SqlHandler());
        server.createContext("/rce", new RceHandler());
        server.createContext("/read", new ReadHandler());
        server.createContext("/", new RootHandler());

        server.setExecutor(null);
        server.start();
    }

    // -- Helpers
    static Map<String, String> queryToMap(String query) {
        Map<String, String> result = new HashMap<>();
        if (query == null || query.isEmpty()) return result;
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            try {
                if (idx > 0) {
                    String key = URLDecoder.decode(pair.substring(0, idx), "UTF-8");
                    String value = URLDecoder.decode(pair.substring(idx + 1), "UTF-8");
                    result.put(key, value);
                } else {
                    result.put(URLDecoder.decode(pair, "UTF-8"), "");
                }
            } catch (UnsupportedEncodingException ignored) { }
        }
        return result;
    }

    static void sendText(HttpExchange t, int code, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        t.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        t.sendResponseHeaders(code, bytes.length);
        OutputStream os = t.getResponseBody();
        os.write(bytes);
        os.close();
    }

    // -- Root handler (links)
    static class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            String body = "<html><body>"
                    + "<h2>VulnerableApp</h2>"
                    + "<ul>"
                    + "<li>/xss?input=... (reflected XSS)</li>"
                    + "<li>/sql?username=... (naive SQL concat)</li>"
                    + "<li>/rce?cmd=... (command injection)</li>"
                    + "<li>/read?path=... (path traversal / file read)</li>"
                    + "</ul>"
                    + "<p>Example: <a href=\"/xss?input=%3Cscript%3Ealert('xss')%3C%2Fscript%3E\">/xss?input=&lt;script&gt;...</a></p>"
                    + "</body></html>";
            sendText(t, 200, body);
        }
    }

    // -- Reflected XSS endpoint (no escaping)
    static class XssHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            URI uri = t.getRequestURI();
            Map<String,String> q = queryToMap(uri.getQuery());
            String input = q.getOrDefault("input", "");
            // Intentionally reflect input back without escaping -> reflected XSS
            String body = "<html><body>"
                    + "<h3>Reflected XSS demo</h3>"
                    + "<p>You sent: " + input + "</p>"
                    + "</body></html>";
            sendText(t, 200, body);
        }
    }

    // -- Naive SQL-like endpoint (string concatenation)
    static class SqlHandler implements HttpHandler {
        // simulated "users" table
        static final List<String> USERS = Arrays.asList("alice", "bob", "carol");

        @Override
        public void handle(HttpExchange t) throws IOException {
            URI uri = t.getRequestURI();
            Map<String,String> q = queryToMap(uri.getQuery());
            String username = q.getOrDefault("username", "");

            // Intentionally vulnerable SQL string concatenation
            String sql = "SELECT id, username FROM users WHERE username = '" + username + "';";
            StringBuilder body = new StringBuilder();
            body.append("<html><body>");
            body.append("<h3>SQL Injection demo (simulated)</h3>");
            body.append("<pre>Query: ").append(escapeHtml(sql)).append("</pre>");

            // Simulated execution: naive check for common injection payloads
            if (username.toLowerCase().contains("or '1'='1") || username.toLowerCase().contains("\" or \"1\"=\"1")) {
                body.append("<p><b>Condition matched - returning ALL users (simulated)</b></p>");
                body.append("<ul>");
                for (String u : USERS) body.append("<li>").append(u).append("</li>");
                body.append("</ul>");
            } else {
                // simulate lookup
                if (USERS.contains(username)) {
                    body.append("<p>Found user: ").append(escapeHtml(username)).append("</p>");
                } else {
                    body.append("<p>No user found for: ").append(escapeHtml(username)).append("</p>");
                }
            }
            body.append("</body></html>");
            sendText(t, 200, body.toString());
        }

        // small helper to escape the SQL text in HTML view
        static String escapeHtml(String s) {
            return s.replace("&", "&amp;").replace("<","&lt;").replace(">","&gt;");
        }
    }

    // -- Command execution endpoint (unsanitized Runtime.exec)
    static class RceHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            URI uri = t.getRequestURI();
            Map<String,String> q = queryToMap(uri.getQuery());
            String cmd = q.getOrDefault("cmd", "");
            StringBuilder body = new StringBuilder();
            body.append("<html><body>");
            body.append("<h3>Remote Command Execution demo (intentional)</h3>");
            body.append("<p>Running: <code>").append(escapeHtml(cmd)).append("</code></p>");

            if (cmd.isEmpty()) {
                body.append("<p>No cmd provided. Try <code>?cmd=whoami</code> or <code>?cmd=ls -la</code></p>");
            } else {
                try {
                    // UNSAFE: directly executing user input
                    Process p = Runtime.getRuntime().exec(cmd);
                    InputStream is = p.getInputStream();
                    BufferedReader br = new BufferedReader(new InputStreamReader(is));
                    String line;
                    body.append("<pre>");
                    while ((line = br.readLine()) != null) {
                        body.append(escapeHtml(line)).append("\n");
                    }
                    body.append("</pre>");
                } catch (Exception e) {
                    body.append("<p>Error executing command: ").append(escapeHtml(e.toString())).append("</p>");
                }
            }

            body.append("</body></html>");
            sendText(t, 200, body.toString());
        }

        static String escapeHtml(String s) {
            if (s == null) return "";
            return s.replace("&", "&amp;").replace("<","&lt;").replace(">","&gt;");
        }
    }

    // -- Arbitrary file read endpoint (path traversal)
    static class ReadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            URI uri = t.getRequestURI();
            Map<String,String> q = queryToMap(uri.getQuery());
            String path = q.getOrDefault("path", "");

            StringBuilder body = new StringBuilder();
            body.append("<html><body>");
            body.append("<h3>File Read demo (path traversal allowed)</h3>");
            body.append("<p>Requested path: <code>").append(escapeHtml(path)).append("</code></p>");

            if (path.isEmpty()) {
                body.append("<p>Give a path like <code>?path=/etc/hosts</code> (Unix) or <code>?path=C:\\\\Windows\\\\win.ini</code> (Windows)</p>");
            } else {
                File f = new File(path);
                if (!f.exists() || !f.isFile()) {
                    body.append("<p>File not found or not a regular file.</p>");
                } else {
                    body.append("<pre>");
                    try (BufferedReader br = new BufferedReader(new FileReader(f))) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            body.append(escapeHtml(line)).append("\n");
                        }
                    } catch (Exception e) {
                        body.append("Error reading file: ").append(escapeHtml(e.toString()));
                    }
                    body.append("</pre>");
                }
            }

            body.append("</body></html>");
            sendText(t, 200, body.toString());
        }

        static String escapeHtml(String s) {
            if (s == null) return "";
            return s.replace("&", "&amp;").replace("<","&lt;").replace(">","&gt;");
        }
    }
}

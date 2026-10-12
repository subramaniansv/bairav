package demo;

import java.security.MessageDigest;
import java.util.List;

@CrossOrigin(origins = "*")
public class UserController {
    private String apiKey = "sk_live_1234567890abcdef";

    @OneToMany(fetch = FetchType.EAGER)
    List<Object> orders;

    public Object find(String name) throws Exception {
        String q = "SELECT * FROM users WHERE name = '" + name + "'";
        MessageDigest md = MessageDigest.getInstance("MD5");
        Thread.sleep(100);
        System.out.println(q);
        return repo.findAll();
    }
}

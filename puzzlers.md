---
title: Java AppSec Puzzlers
author: Josh Cummings
date: 2022-11-10
patat:
  pandocExtensions:
    - patat_extensions
    - autolink_bare_uris
    - emoji
...

# whoami

Hi, I'm Josh Cummings.

I've worked on Spring Security for about the last 5 years.
I've worked with it for much longer (c. 2008)

## Points of Interest

I have seven children and one wife.
I like to juggle.

## Level of Java Fame Continuum

|--Josh Cummings-----------------------Josh Long-------------Josh Bloch--|

---

# Objective

Earn more points than your buddy

# Scoring

- **One** point per vulnerability found
- **One** point per mitigation described
- **Five** points per CVE identified

# Caveat

This is *Java* AppSec Puzzlers, it's all written in Java.
Feel free to ask for clarity if you don't know what something is doing.

---

# Puzzle One

```java
@Controller
public final class PageController {
    private final PasswordEncoder encoder = new Md5PasswordEncoder();

    // .. constructor

    @RequestMapping("/login")
    public String login(
        @RequestParam("username") String username, @RequestParam("password") String password) {
        String userPassword = userService.findByUsername(username);
        String hashed = encoder.encode(password);
        if (userPassword.equals(password)) {
            return "redirect:/home";
        }
        model.setAttribute("errorMessage", username + " is incorrect");
        return "login";
    }
}
```

---

# Puzzle One Answers

. . .

## MD5?! :angry:
  => MD5 is prone to collisions and doesn't have enough entropy for modern systems
  => Use a stronger encoding algorithm like Argon2 or BCrypt

. . .

## `@RequestMapping`
  => it can be invoked as a `GET` or any other allowed HTTP method
  => perform login without knowledge of user (aka CSRF login)
  => potential CPU DoS
 
. . . 

## Null Check, Username Oracle

  => Because behavior is different for good vs bad passwords, this endpoint can be used to guess usernames

. . .

## `.equals`
  => Timing Attack

. . .

## concatenation of user input 
  => XSS and other possible injections
   
---

# Puzzle One Lessons Learned

> - Read and reference [OWASP's Password Storage article](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
> - Specify which HTTP method to use; `@PostMapping`, `@GetMapping`, etc.
> - Validate Input
> - For multi-step security operations, try and keep the same number of steps
> - *Don't* reflect user's unfiltered input back
> - Give yourself a solid pinch if you find yourself concatentating user input

**Points Possible**: ~12

---

# Puzzle Two

```java
public final class LoggerHelper {
  private final HttpServletRequest request;

  // ... constructor

  public void info(String message) {
    logger.info("sessionId = [%s]: %s", request.getSession().getId(), message);
  }
}
```

---

# Puzzle Two Answers

## Logging of Session Id

  => Internal support can use session id to hijack user's session

. . .

## Using `request.getSession()`

  => `getSession()` will create a session if none exists, potential resource leak

---

# Puzzle Two Lessons Learned

> - Don't log sensitive information.
> - Don't log sensitive information.
> - If you must log sensitive information, hash it.
> - Don't log sensitive information.
> - Use `getSession(false)` by default - something in your platform infra should be the one creating a session

**Points Possible**: ~7

---

# Puzzle Three

```java
@RestController
public class MessageController {
  @GetMapping("/echo")
  public String echo(@RequestParam("message") String message) {
    logger.info("Sending Message " + message);
  }
}
```

---

# Puzzle Three Answers

## Concatenating Untrusted User Input

  => Injection of Fake Logs
  => If using an unpatched Log4J... RCE, Code Hoisting, Sensitive Data Exposure, and on and on
  => [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)


---

# Puzzle Three Lessons Learned

> - Keep dependencies up to date
> - Don't concatenate untrusted input
> - Consider parameterization
> - Consider open source health metrics and SLSA
> - Whitelist ports
> - Use native compilation

**Possible Points**: ~1024

---

# Puzzle Four

```
public final class MyAuthenticator {
  private static final String WORK_FACTOR = 31;
  private final PasswordEncoder encoder = new BCryptPasswordEncoder(WORK_FACTOR);
  
  public boolean matches(String rawPassword, String encoded) {
    return this.encoder.matches(rawPassword, encoded);
  }
}
```

---

# Puzzle Four Answers

## Usage of Impractical Work Factor

  => A work factor of 31 will take modern hardware 2-3 days **per hash**
  => Due to a bug in `BCrypt`, zero hashes were performed
  => [CVE-2022-22976](https://tanzu.vmware.com/security/cve-2022-22976)

```java
int rounds = 2 << log_rounds;
```

(can you spot the issue?)

---

# Puzzle Four Lessons Learned

> - Read and reference [OWASP's Password Storage article](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
> - Gain a basic undertanding of the hashing algorithm you are using
> - Use a hashing algorithm that has its settings embedded in the hash
> - Think about boundary cases and use the right datatype

**Points Possible**: ~10

---

# Puzzle Five

```java
public class Coffee implements Serializable {

    private final String name;
    private final double cost;
    
    public Coffee(String name, double cost) {
       Assert.notEmpty(name, "name must not be empty");
       Assert.isTrue(cost > 0, "cost must be greater than zero");
       this.name = name;
       this.cost = cost;
    }

    // .. getters
}
```

and:

```java
@RestController("/coffee")
public final class CoffeeController {
    @GetMapping("/list")
    public List<Coffee> listCoffee() throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("coffee.ser"));
        return (List<Coffee>) ois.readObject();
    }

    @PostMapping
    public void addCoffee(@RequestParam("name") String name, @RequestParam("cost") double cost) 
        throws Exception {
        List<Coffee> coffee = listCoffee();
        coffee.add(new Coffee(name, cost));
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("coffee.ser"));
        oos.writeObject();
	oos.close();
    }
}
```

---

# Puzzle Five Answers

. . .

# Insecure deserialization

  => edit the file out-of-band to bypass ``Coffee``'s invariants
  => edit the file out-of-band to deserialize into a deserialization gadget
  => once deserialization gadget is introduced, RCEs are rather simple
  => [several CVEs](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=jackson+gadgets)

. . .

# Resource Leakage

  => No closing of input stream, potential DoS
  => No guaranteed closing of output stream, potential DoS

. . .

# Concurrency

  => A single file cannot be opened in `write-mode` by multiple threads at the same time 

---

# Puzzle Five Lessons Learned

> - Don't use Java serialization (Jackson without `enableDefaultTyping` is a viable option)
> - Infer typing internally
> - Keep dependencies up to date
> - Favor composition
> - If you must use serialization, intercept the stream and only deserialize a whitelist of Java types :skull: hard :skull: - consider `readResolve`
> - Use `try-with-resources`
> - Use a `Lock`

**Points Possible**: Several

---

# Puzzle Six

```java
@Controller
public final class CachingFilter {
  private final Map<String, String> requestById = new HashMap<>();

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
    if (userIsLoggedIn(request)) {
      String guid = request.getParameter("guid");
      if (guid == null) {
        chain.doFilter(request, response);
        return;
      }
      String uri = requestById.get(guid);
      if (uri == null) {
        chain.doFilter(request, response);
        return;
      }
      response.sendRedirect(requestById);
    }
    String guid = UUID.randomUUID().toString();
    requestById.put(guid, request.getRequestURI());

    response.sendRedirect("/login?guid=" + guid);
  }
}
```

---

# Puzzle Six Answers

## Unbounded Cache

  => Malicious user can exhaust memory by hitting this endpoint to generate guids and fill the map
  => [CVE-2021-22119](https://tanzu.vmware.com/security/cve-2021-22119)

---

# Puzzle Six Lessons Learned

> - Ensure caches have an upper bound and a clear eviction strategy (preferrably time-based)
> - Consider tying data to the session instead of re-inventing it

**Points Possible**: ~9

---

# Puzzle Seven

```java
@RestController
public final class ConfigController {
    @GetMapping
    public void uploadConfiguration(@RequestParam("file") MultipartFile file) throws Exception {
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	DocumentBuilder builder = factory.newDocumentBuilder();
	Element root = builder.parse(new InputSource(file.getInputStream())).getDocumentElement();
        configurationService.save(root);
    }
}
```

---

# Puzzle Seven Answers

## XXE

  => Java defaults allow `DOCTYPE` headers that include ``DTD``s and entity resolution
  => XML bombs through recursive references
  => SSRF, exfiltration of data

. . .

## Resource Leakage

  => Forgot to close `InputStream` again ;)

---

# Puzzle Seven Lessons Learned

> - Declare defaults
> - Remove unwanted features
> - Close input streams

---

# How did you do??

* **0-10** - Argus Filch 
* **10-25** - Hagrid
* **25-50** - Madeye Moody
* **50+** - Albus Dumbledore

---

# Final Thoughts

- Take time to learn and practice
- OWASP is a good start
- Pluralsight Java Web Application Security Courses
- Watch for me and the team on Spring Office Hours

- The target has already started to move
-- Supply Chain attacks
-- SLSA is important
-- Open-source metrics is important


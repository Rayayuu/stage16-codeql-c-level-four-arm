import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

/**
 * CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
 *
 * This query tracks attacker-controlled identifiers taken from HTTP requests
 * (Servlet API, Spring MVC, JAX-RS) or external identity keys (Principal/X500Principal),
 * and reports flows into sensitive resource-modifying operations (delete/remove/update/modify).
 *
 * It also models flows of externally-supplied identity keys into authorization/permission checks,
 * which may indicate authorization that relies on user-controlled keys.
 *
 * To reduce false positives, results are suppressed when the enclosing handler clearly uses
 * an authentication context (e.g., Principal/Authentication parameter or Spring SecurityContextHolder),
 * a common remediation pattern for IDOR.
 */

/** ID-like formal parameter heuristic. */
private predicate isIdLike(Parameter p) {
  p.getName().matches("(?i).*(id|uuid|guid).*")
}

/** Methods that likely perform sensitive modifications on resources. */
private predicate isSensitiveOperationName(string n) {
  n.matches("(?i)(delete|remove|update|modify|change|edit).*")
}

/** Methods that likely perform authorization/permission decisions. */
private predicate isAuthzDecisionName(string n) {
  n.matches("(?i)(isAuthorized|isAuthorised|authorize|authorise|isAllowed|hasPermission|hasAuthority|checkPerm|checkAuth|authorizeRequest|validatePerm).*")
}

/** Spring MVC request-bound parameter annotations. */
private predicate hasSpringWebBindingAnnotation(Parameter p) {
  exists(Annotation a |
    p.hasAnnotation(a) and
    (
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody")
    )
  )
}

/** JAX-RS request-bound parameter annotations. */
private predicate hasJaxRsBindingAnnotation(Parameter p) {
  exists(Annotation a |
    p.hasAnnotation(a) and
    (
      a.getType().hasQualifiedName("javax.ws.rs", "PathParam") or
      a.getType().hasQualifiedName("javax.ws.rs", "QueryParam") or
      a.getType().hasQualifiedName("javax.ws.rs", "HeaderParam") or
      a.getType().hasQualifiedName("javax.ws.rs", "FormParam") or
      a.getType().hasQualifiedName("jakarta.ws.rs", "PathParam") or
      a.getType().hasQualifiedName("jakarta.ws.rs", "QueryParam") or
      a.getType().hasQualifiedName("jakarta.ws.rs", "HeaderParam") or
      a.getType().hasQualifiedName("jakarta.ws.rs", "FormParam")
    )
  )
}

/** Servlet request APIs returning user-controlled data. */
private predicate isServletRequestGetter(Method m) {
  m.getName().matches("getParameter|getParameterValues|getHeader|getQueryString|getPathInfo|getRequestURI") and
  (
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") or
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") or
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletRequest") or
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest")
  )
}

/** Principal/X500Principal identity getters (external identity keys). */
private predicate isPrincipalNameGetter(Method m) {
  m.getName() = "getName" and
  (
    m.getDeclaringType().hasQualifiedName("java.security", "Principal") or
    m.getDeclaringType().hasQualifiedName("javax.security.auth.x500", "X500Principal")
  )
}

/** Heuristic: enclosing callable uses an authentication context, suggesting safer ownership derivation. */
private predicate hasAuthContext(Callable c) {
  exists(Parameter p |
    p.getDeclaringCallable() = c and
    (
      p.getType().(RefType).hasQualifiedName("java.security", "Principal") or
      p.getType().(RefType).hasQualifiedName("org.springframework.security.core", "Authentication")
    )
  )
  or
  exists(MethodCall mc |
    mc.getEnclosingCallable() = c and
    mc.getMethod().getDeclaringType().hasQualifiedName("org.springframework.security.core.context", "SecurityContextHolder")
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Spring/JAX-RS request-bound parameters
    exists(Parameter p |
      (hasSpringWebBindingAnnotation(p) or hasJaxRsBindingAnnotation(p)) and
      source = DataFlow::parameterNode(p)
    )
    or
    // Servlet request getters
    exists(MethodCall mc |
      isServletRequestGetter(mc.getMethod()) and
      source.asExpr() = mc
    )
    or
    // External identity keys via Principal/X500Principal name
    exists(MethodCall mc |
      isPrincipalNameGetter(mc.getMethod()) and
      source.asExpr() = mc
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // Sensitive resource-modifying operations taking an ID-like argument
    exists(Call c, Callable target, Method m, Expr arg, int i |
      target = c.getCallee() and
      m = target and
      isSensitiveOperationName(m.getName()) and
      arg = c.getArgument(i) and
      sink.asExpr() = arg and
      exists(Parameter fp |
        fp = m.getParameter(i) and isIdLike(fp)
      ) and
      not hasAuthContext(c.getEnclosingCallable())
    )
    or
    // Authorization decision APIs consuming externally supplied identity keys
    exists(Call c, Callable target, Method m, Expr arg, int i |
      target = c.getCallee() and
      m = target and
      isAuthzDecisionName(m.getName()) and
      arg = c.getArgument(i) and
      sink.asExpr() = arg
    )
  }
}

module Flow = TaintTracking::Global<Config>;

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(),
  "User-controlled identifier flows into a sensitive operation or authorization decision, which may enable IDOR.",
  source, sink

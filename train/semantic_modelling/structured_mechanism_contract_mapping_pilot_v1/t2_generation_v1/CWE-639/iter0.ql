import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

/**
 * @name User-controlled identifier used in sensitive operation (possible IDOR)
 * @description Detects flows where a user-controlled identifier from HTTP/web inputs is used as an argument to a sensitive resource operation (delete/remove/update/modify/etc.) without an evident authorization/ownership context. This heuristic captures common CWE-639 patterns.
 * @kind problem
 * @problem.severity warning
 * @id java/cwe-639/user-controlled-identifier-to-sensitive-operation
 */

/** Helper: Spring MVC request-mapping annotation? */
private predicate isSpringRequestMappingAnnotation(Annotation a) {
  exists(RefType t |
    t = a.getType() and
    t.hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping") or
    t.hasQualifiedName("org.springframework.web.bind.annotation", "GetMapping") or
    t.hasQualifiedName("org.springframework.web.bind.annotation", "PostMapping") or
    t.hasQualifiedName("org.springframework.web.bind.annotation", "PutMapping") or
    t.hasQualifiedName("org.springframework.web.bind.annotation", "DeleteMapping") or
    t.hasQualifiedName("org.springframework.web.bind.annotation", "PatchMapping")
  )
}

/** Helper: Method is a Spring MVC handler (annotated with a mapping). */
private predicate isSpringHandler(Method m) {
  exists(Annotation a | a = m.getAnAnnotation() and isSpringRequestMappingAnnotation(a))
}

/** Helper: JAX-RS parameter annotations indicating request-sourced values. */
private predicate isJaxrsParamAnnotation(Annotation a) {
  exists(RefType t |
    t = a.getType() and
    t.hasQualifiedName("javax.ws.rs", "PathParam") or
    t.hasQualifiedName("javax.ws.rs", "QueryParam") or
    t.hasQualifiedName("javax.ws.rs", "FormParam")
  )
}

/** Helper: HttpServletRequest accessors commonly used to read user input. */
private predicate isHttpRequestAccessor(MethodCall mc) {
  mc.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
  mc.getMethod().getName().matches("getParameter|getHeader|getQueryString|getParameterValues|getParameterMap")
}

/** Helper: name looks like an identifier key (id/userId/uuid/key/token/etc.). */
private predicate isIdLikeName(string n) {
  n = "id" or n = "uid" or
  n = "ID" or n = "UID" or
  n.matches("%id") or n.matches("%Id") or n.matches("%ID") or
  n.matches("%uid") or n.matches("%Uid") or n.matches("%UID") or
  n.matches("%uuid") or n.matches("%Uuid") or n.matches("%UUID") or
  n.matches("%guid") or n.matches("%Guid") or n.matches("%GUID") or
  n.matches("%key") or n.matches("%Key") or n.matches("%KEY") or
  n.matches("%token") or n.matches("%Token") or n.matches("%TOKEN") or
  n.matches("%PanelId") or n.matches("%MessageId") or n.matches("%UserId") or n.matches("%ConfigId") or n.matches("%ShareId")
}

/** Helper: literal value looks like an identifier key label. */
private predicate isIdLikeLiteral(StringLiteral sl) {
  sl.getValue() = "id" or sl.getValue() = "uid" or
  sl.getValue().matches("%id") or sl.getValue().matches("%Id") or sl.getValue().matches("%ID") or
  sl.getValue().matches("%uid") or sl.getValue().matches("%Uid") or sl.getValue().matches("%UID") or
  sl.getValue().matches("%uuid") or sl.getValue().matches("%Uuid") or sl.getValue().matches("%UUID") or
  sl.getValue().matches("%guid") or sl.getValue().matches("%Guid") or sl.getValue().matches("%GUID") or
  sl.getValue().matches("%key") or sl.getValue().matches("%Key") or sl.getValue().matches("%KEY") or
  sl.getValue().matches("%token") or sl.getValue().matches("%Token") or sl.getValue().matches("%TOKEN") or
  sl.getValue().matches("%panelId") or sl.getValue().matches("%messageId") or sl.getValue().matches("%userId") or sl.getValue().matches("%configId") or sl.getValue().matches("%shareId")
}

/** Helper: expression appears to be an identifier/key. */
private predicate isIdLikeExpr(Expr e) {
  exists(VariableAccess va | e = va and isIdLikeName(va.getTarget().getName())) or
  exists(FieldAccess fa | e = fa and isIdLikeName(fa.getTarget().getName())) or
  exists(MethodCall mc, Expr key, StringLiteral sl |
    e = mc and isHttpRequestAccessor(mc) and key = mc.getArgument(0) and sl = key and isIdLikeLiteral(sl)
  )
}

/** Helper: method name suggests a sensitive resource-modifying operation. */
private predicate isSensitiveOperationName(string n) {
  n.matches("delete%") or n.matches("remove%") or n.matches("update%") or n.matches("modify%") or
  n.matches("set%") or n.matches("save%") or n.matches("change%") or n.matches("grant%") or n.matches("revoke%") or
  n.matches("share%") or n.matches("unshare%") or n.matches("bind%") or n.matches("assign%") or
  n.matches("disable%") or n.matches("enable%") or n.matches("approve%") or n.matches("reject%") or
  n.matches("clear%") or n.matches("reset%") or n.matches("subscribe%") or n.matches("unsubscribe%") or
  n.matches("cancel%") or n.matches("close%") or n.matches("open%") or n.matches("start%") or n.matches("stop%")
}

/** Helper: callable has an evident authorization context (reduce FPs). */
private predicate hasAuthorizationContext(Callable c) {
  exists(Parameter p |
    p.getDeclaringCallable() = c and p.getType() instanceof RefType and
    (
      p.getType().(RefType).hasQualifiedName("java.security", "Principal") or
      p.getType().(RefType).hasQualifiedName("org.springframework.security.core", "Authentication")
    )
  ) or
  exists(MethodCall mc |
    mc.getEnclosingCallable() = c and
    mc.getMethod().getDeclaringType().hasQualifiedName("org.springframework.security.core.context", "SecurityContextHolder")
  )
}

module IDORConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Servlet request accessors
    exists(MethodCall mc |
      isHttpRequestAccessor(mc) and source.asExpr() = mc
    )
    or
    // Spring MVC handler parameters (any parameter is user-controlled)
    exists(Method m, Parameter p |
      isSpringHandler(m) and p.getDeclaringCallable() = m and source.asParameter() = p
    )
    or
    // JAX-RS annotated parameters
    exists(Parameter p, Annotation a |
      a = p.getAnAnnotation() and isJaxrsParamAnnotation(a) and source.asParameter() = p
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Call c, int i, Expr arg |
      arg = c.getArgument(i) and sink.asExpr() = arg and isIdLikeExpr(arg) and
      exists(Callable target | target = c.getCallee() and isSensitiveOperationName(target.getName()))
    )
  }
}

module Flow = TaintTracking::Global<IDORConfig>;

from Flow::PathNode source, Flow::PathNode sink, Callable ec
where
  Flow::flowPath(source, sink) and
  ec = sink.getNode().asExpr().getEnclosingCallable() and
  not hasAuthorizationContext(ec)
select sink.getNode(),
  "User-controlled identifier flows into a sensitive operation; ensure ownership/authorization is verified."

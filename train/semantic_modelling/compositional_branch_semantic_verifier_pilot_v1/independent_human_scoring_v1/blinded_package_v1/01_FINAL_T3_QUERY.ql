/*
 * T3 deterministic composition.
 *
 * Accepted mechanism branches are inserted byte-for-byte without
 * semantic rewriting. Rejected or failed branches are intentionally
 * omitted and are not replaced by generic surrogates.
 */

import java
import semmle.code.java.dataflow.DataFlow

module T3BranchCertificateReuse {

  /** Certificate attribute getters on X509Certificate */
  private predicate isX509CertMethod(Method m) {
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509Certificate") or
    m.getDeclaringType().hasQualifiedName("javax.security.cert", "X509Certificate")
  }

  private predicate isCertAttributeGetter(Method m) {
    isX509CertMethod(m) and
    (
      m.getName().regexpMatch("getSubject(X500Principal|DN)") or
      m.getName() = "getSubjectAlternativeNames" or
      m.getName() = "getSerialNumber"
    )
  }

  /**
   * Heuristically recognize expressions derived from certificate attributes used as identity keys.
   * Either direct getters on X509Certificate, or getName() on X500Principal when the same scope
   * also calls getSubjectX500Principal on a certificate.
   */
  private predicate isCertAttrExpr(Expr e) {
    exists(MethodCall mc, Method m |
      mc = e and m = mc.getMethod() and isCertAttributeGetter(m)
    )
    or
    exists(MethodCall mcName, Method mName, MethodCall mcSubject, Method mSubject |
      mcName = e and mName = mcName.getMethod() and
      mName.getName() = "getName" and
      mName.getDeclaringType().getName().regexpMatch("X500Principal") and
      mcName.getEnclosingCallable() = mcSubject.getEnclosingCallable() and
      mSubject = mcSubject.getMethod() and
      isX509CertMethod(mSubject) and mSubject.getName() = "getSubjectX500Principal"
    )
  }

  /** Methods that establish or set an authenticated identity/session. */
  private predicate isAuthEstablish(Method m) {
    m.getName().regexpMatch("(authenticate|authenticat.*WithCert|login|logIn|createSession|startSession|setAuthenticated|setUser|setPrincipal|assumeUser|impersonat|switchUser|authorize)")
  }

  /**
   * Decisive security relation: certificate attribute is mapped directly to an authenticated identity/session argument.
   */
  private predicate hasWeakMapping(Call c, Expr id) {
    c.getCallee() instanceof Method and
    isAuthEstablish(c.getCallee().(Method)) and
    exists(int i | id = c.getArgument(i)) and
    isCertAttrExpr(id)
  }

  /** Presence of validation/scoping that should gate certificate-to-identity mapping. */
  private predicate hasValidationInScope(Callable scope) {
    exists(Call v |
      v.getEnclosingCallable() = scope and
      (
        exists(Callable cal |
          cal = v.getCallee() and
          (
            cal.getName().regexpMatch("(verify|validat|check|scope|restrict|enforc|match|trust|isAuthorized|hasRole)") or
            cal.getName().regexpMatch("get(ExtendedKeyUsage|KeyUsage|BasicConstraints|IssuerX500Principal)") or
            cal.getName() = "checkValidity"
          )
        )
      )
    )
  }

  /**
   * Exposed branch interface: sink is the certificate-derived identity used to establish an authenticated session/identity
   * without sufficient validation/scoping.
   */
  predicate result(DataFlow::Node sink) {
    exists(Call c, Expr id |
      hasWeakMapping(c, id) and
      not hasValidationInScope(c.getEnclosingCallable()) and
      sink = DataFlow::exprNode(id)
    )
  }
}


from DataFlow::Node sink
where T3BranchCertificateReuse::result(sink)
select sink,
  "CWE-639 T3 accepted mechanism branch: improper_authentication_certificate_reuse."

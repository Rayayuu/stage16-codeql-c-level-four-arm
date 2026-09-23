module T3BranchOptionalIdentity {

  private predicate looksLikeIdentityName(string n) { n.regexpMatch("(?i).*(sasl|instance|auth|principal|identity|user|client|peer|member|config|param|option|key|id).*") }

  private predicate looksLikeAuthCheckName(string n) { n.regexpMatch("(?i).*(auth|authorize|permission|perm|allow|check|validate|verify).*") }

  private predicate looksLikePresenceTestName(string n) { n.regexpMatch("(?i).*(isEmpty|has|present|isPresent|contains|exists|notNull|nonNull|length).*") }

  private predicate looksLikeSensitiveOpName(string n) { n.regexpMatch("(?i).*(join|cluster|quorum|peer|server|member|leader|reconfig|reconfigure|setConfig|updateConfig|applyConfig|setOption|setParam|enable|disable|allow|permit).*") }

  /** Identity component expression such as SASL instance, principal, or config/param key/value. */
  private predicate isIdentityExpr(Expr e) {
    // Direct getter-style method call returning identity/config elements
    exists(MethodCall mc, Method m |
      e = mc and m = mc.getMethod() and looksLikeIdentityName(m.getName())
    )
    or
    // An argument flowing into a call whose callee name suggests identity/config context
    exists(Call c, Expr a, int i, Callable cal |
      e = a and a = c.getArgument(i) and cal = c.getCallee() and looksLikeIdentityName(cal.getName())
    )
  }

  // Lightweight ID taint config so presence/authorization conditions can be tied to the same identity component.
  module IdConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { exists(Expr e | isIdentityExpr(e) and source = DataFlow::exprNode(e)) }
    predicate isSink(DataFlow::Node sink) { exists(Expr e | sink = DataFlow::exprNode(e)) }
  }
  module IDFlow = TaintTracking::Global<IdConfig>;

  private predicate flowsTo(Expr src, Expr dst) {
    IDFlow::flow(DataFlow::exprNode(src), DataFlow::exprNode(dst))
  }

  /** Presence/optionality test that depends on the identity component (e.g., id == null, id.isEmpty(), map.containsKey(id)). */
  private predicate isPresenceTestUsing(Expr id, Call presence) {
    exists(Callable cal |
      cal = presence.getCallee() and looksLikePresenceTestName(cal.getName()) and
      (
        exists(int i | flowsTo(id, presence.getArgument(i))) or
        exists(MethodCall mc | presence = mc and flowsTo(id, mc.getReceiver()))
      )
    )
  }

  /** Authorization/validation routine that takes the identity component. */
  private predicate isAuthCheckUsing(Expr id, Call auth) {
    exists(Callable cal |
      cal = auth.getCallee() and looksLikeAuthCheckName(cal.getName()) and
      exists(int i | flowsTo(id, auth.getArgument(i)))
    )
  }

  /** Security-sensitive operation such as joining a cluster or changing sensitive configuration. */
  private predicate isSensitiveOperation(Call c) {
    exists(Callable cal | cal = c.getCallee() and looksLikeSensitiveOpName(cal.getName()))
  }

  /** c appears textually before d in the same file. */
  private predicate appearsBefore(Expr c, Expr d) {
    c.getLocation().getFile() = d.getLocation().getFile() and
    (
      c.getLocation().getStartLine() < d.getLocation().getStartLine() or
      c.getLocation().getStartLine() = d.getLocation().getStartLine() and
      c.getLocation().getStartColumn() < d.getLocation().getStartColumn()
    )
  }

  /** The call is directly under the given branch statement (single stmt or block). */
  private predicate inBranchStmt(Stmt br, Call c) {
    c.getEnclosingStmt() = br
    or exists(Block b | br = b and c.getEnclosingStmt().getParent() = b)
  }

  /** The call resides in the then-branch of the if-statement. */
  private predicate inThen(IfStmt s, Call c) { exists(Stmt br | br = s.getThen() and inBranchStmt(br, c)) }

  /** The call resides in the else-branch of the if-statement. */
  private predicate inElse(IfStmt s, Call c) { exists(Stmt br | br = s.getElse() and inBranchStmt(br, c)) }

  /**
   * If-statement condition uses a presence test and short-circuits authorization on missing/optional identity.
   * Both the presence-test call and the auth-check call occur in the same if-condition, with presence evaluated before auth.
   */
  private predicate ifGuardsAuthViaPresence(Expr id, Call presence, Call auth, IfStmt s) {
    isIdentityExpr(id) and
    isPresenceTestUsing(id, presence) and
    isAuthCheckUsing(id, auth) and
    presence.getEnclosingStmt() = s and
    auth.getEnclosingStmt() = s and
    appearsBefore(presence, auth)
  }

  // Decisive security relation: authorization logic branches based on presence/value of the key; missing/optional component causes checks to be skipped.
  private predicate decisive_security_relation(Expr id, Call presence, Call auth) {
    exists(IfStmt s | ifGuardsAuthViaPresence(id, presence, auth, s))
  }

  // Required condition: presence and validation of the identity component must be enforced before privileged operation.
  private predicate required_validation_or_authorization_condition(Expr id, Call auth) {
    isAuthCheckUsing(id, auth)
  }

  // Report sensitive operations reachable in a context where authorization is contingent on an optional/missing identity component
  // and is bypassed along the branch that reaches the sensitive operation.
  predicate result(DataFlow::Node sink) {
    exists(Expr id, Call presence, Call auth, Call sens, IfStmt s |
      ifGuardsAuthViaPresence(id, presence, auth, s) and
      isSensitiveOperation(sens) and
      sens.getEnclosingCallable() = s.getEnclosingCallable() and
      (
        inThen(s, sens) and not exists(Call a2 | isAuthCheckUsing(id, a2) and inThen(s, a2))
        or
        inElse(s, sens) and not exists(Call a3 | isAuthCheckUsing(id, a3) and inElse(s, a3))
      ) and
      sink = DataFlow::exprNode(sens)
    )
  }
}

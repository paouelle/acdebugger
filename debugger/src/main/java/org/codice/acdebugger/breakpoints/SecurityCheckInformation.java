/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.acdebugger.breakpoints;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Charsets;
import com.google.common.io.LineProcessor;
import com.google.common.io.Resources;
import java.io.IOError;
import java.io.IOException;
import java.security.Permission;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import javax.annotation.Nullable;
import org.codice.acdebugger.ACDebugger;
import org.codice.acdebugger.api.Debug;
import org.codice.acdebugger.api.SecurityFailure;
import org.codice.acdebugger.api.SecuritySolution;
import org.codice.acdebugger.api.StackFrameInformation;

/**
 * This class serves 2 purposes. It is first a representation of a detected security check failure.
 * During analysis, it is also used to compute and report possible security solutions to the
 * security failure.
 */
class SecurityCheckInformation extends SecuritySolution implements SecurityFailure {
  static final String DOUBLE_LINES =
      "=======================================================================";

  /**
   * List of patterns to match security check information that should be considered acceptable
   * failures and skipped.
   */
  private static final List<Pattern> ACCEPTABLE_PATTERNS;

  static {
    try {
      ACCEPTABLE_PATTERNS =
          Resources.readLines(
              Resources.getResource("acceptable-security-check-failures.txt"),
              Charsets.UTF_8,
              new PatternProcessor());
    } catch (IOException e) {
      throw new IOError(e);
    }
  }

  /** The associated debug session. */
  private final Debug debug;

  /** The context information retrieved from the AccessControlContext class at line 472. */
  private final AccessControlContextInfo context;

  /**
   * list of protection domains (i.e. bundle name/domain location) in the security context as
   * recomputed here. This list may contain nulls but never duplicate domains.
   */
  private final List<String> domains;

  /**
   * bit set indicating if an entry in the domains list was combined. An entry that came from the
   * stack could potentially be surrounded by a <code>doPrivileged()</code> block and be correlated
   * with the stack information retrieved from the current thread.
   */
  private final BitSet isCombined;

  /**
   * the index in the stack for the frame that doesn't have the failed permission, -1 if no failures
   */
  private int failedStackIndex = -1;

  /**
   * the stack index of the last place (i.e. lowest index) a domain extended its privileges or -1 if
   * none found. Everything between 0 til this index is of interest for the security manager
   */
  private int privilegedStackIndex = -1;

  /**
   * the domain names right after the doPrivileged() block doing it on behalf of its caller and up
   * to the end of the stack or up to the next doPrivileged() block not doing it on behalf of its
   * caller. This will help us identify domains that would otherwise be marked combined by the
   * context as not being combined since we know for a fact they come from the stack and therefore
   * can be analyzed to have solutons including insertions of doPrivileged() blocks.
   */
  private Set<String> onBehalfOfCallerPrivilegedDomains;

  /**
   * index in the domains list where we recomputed the reported security exception to be generated
   * for or <code>-1</code> if no failures.
   */
  private int failedDomainIndex = -1;

  private final boolean invalid;

  /** First pattern that was matched indicating the failure was acceptable. */
  @Nullable private Pattern acceptablePattern = null;

  @Nullable private List<SecuritySolution> analysis = null;

  /**
   * Creates a security check failure from a given access control context.
   *
   * @param debug the current debug session
   * @param context the context information to be analyzed
   * @throws Exception if unable to create a new security check failure
   */
  @SuppressWarnings("squid:S00112" /* Forced to by the Java debugger API */)
  SecurityCheckInformation(Debug debug, AccessControlContextInfo context) throws Exception {
    super(
        debug.threadStack(),
        context.getPermissions(),
        Collections.emptySet(),
        Collections.emptyList());
    final int size = context.getDomains().size();

    this.debug = debug;
    this.context = context;
    this.domains = new ArrayList<>(size);
    this.isCombined = new BitSet(size);
    if (context.getCurrentDomain() == null) {
      // since bundle-0/boot domain always has all permissions, we cannot received null as the
      // current domain where the failure occurred
      dumpTroubleshootingInfo(
          "AN ERROR OCCURRED WHILE ATTEMPTING TO FIND THE LOCATION FOR A DOMAIN");
      throw new Error(
          "unable to find location for domain: "
              + context.getCurrentDomainReference().type().name());
    }
    this.onBehalfOfCallerPrivilegedDomains = new HashSet<>(8);
    this.invalid = !recompute();
    analyze0();
  }

  /**
   * Creates a possible solution as if we granted the missing permission to the failed domain to be
   * analyzed for the given security check failure.
   *
   * @param failure the security check failure for which to create a possible solution
   */
  private SecurityCheckInformation(SecurityCheckInformation failure) {
    super(failure);
    final String failedDomain = failure.getFailedDomain();
    final int size = failure.domains.size();

    this.debug = failure.debug;
    // add the failed domain from the specified failure as a privileged and as a granted one
    super.grantedDomains.add(failedDomain);
    this.context = failure.context.grant(failedDomain);
    this.domains = new ArrayList<>(size);
    this.isCombined = new BitSet(size);
    this.onBehalfOfCallerPrivilegedDomains =
        new HashSet<>(failure.onBehalfOfCallerPrivilegedDomains);
    this.invalid = !recompute();
  }

  /**
   * Creates a possible solution as if we were extending privileges of the domain at the specified
   * stack index to be analyzed for the given security check failure.
   *
   * @param failure the security check failure for which to create a possible solution
   * @param index the index in the stack where to extend privileges
   */
  private SecurityCheckInformation(SecurityCheckInformation failure, int index) {
    super(failure, index);
    final int size = failure.domains.size();

    this.debug = failure.debug;
    this.context = failure.context;
    this.domains = new ArrayList<>(size);
    this.isCombined = new BitSet(size);
    this.onBehalfOfCallerPrivilegedDomains =
        new HashSet<>(failure.onBehalfOfCallerPrivilegedDomains);
    this.invalid = !recompute();
  }

  /**
   * Gets the domain where the failure was detected.
   *
   * @return the domain where the failure was detected or <code>null</code> if no failure is
   *     recomputed from the solution
   */
  @Nullable
  public String getFailedDomain() {
    return (failedDomainIndex != -1) ? domains.get(failedDomainIndex) : null;
  }

  @Override
  public boolean isAcceptable() {
    return acceptablePattern != null;
  }

  @Override
  @Nullable
  public String getAcceptablePermissions() {
    return isAcceptable() ? "REGEX: " + acceptablePattern.getPermissionInfos() : null;
  }

  @Override
  public List<SecuritySolution> analyze() {
    return analysis;
  }

  @SuppressWarnings("squid:S106" /* this is a console application */)
  @Override
  public void dump(boolean osgi, String prefix) {
    final String first =
        prefix + (isAcceptable() ? "ACCEPTABLE " : "") + "ACCESS CONTROL PERMISSION FAILURE";

    System.out.println(ACDebugger.PREFIX);
    System.out.println(ACDebugger.PREFIX + first);
    System.out.println(
        ACDebugger.PREFIX
            + IntStream.range(0, first.length())
                .mapToObj(i -> "=")
                .collect(Collectors.joining("")));
    dump0(osgi);
    for (int i = 0; i < analysis.size(); i++) {
      final SecuritySolution info = analysis.get(i);

      System.out.println(ACDebugger.PREFIX);
      System.out.println(ACDebugger.PREFIX + "OPTION " + (i + 1));
      System.out.println(ACDebugger.PREFIX + "--------");
      ((SecurityCheckInformation) info).dump0(osgi);
    }
    if (!analysis.isEmpty()) {
      System.out.println(ACDebugger.PREFIX);
      System.out.println(ACDebugger.PREFIX + "SOLUTIONS");
      System.out.println(ACDebugger.PREFIX + "---------");
      analysis.forEach(s -> s.print(osgi));
    }
  }

  @Override
  public String toString() {
    if (!grantedDomains.isEmpty() || !doPrivileged.isEmpty()) { // we have a solution
      return super.toString();
    }
    final String currentDomain = context.getCurrentDomain();

    if (currentDomain == null) {
      return "";
    }
    if (isAcceptable()) {
      return "Acceptable check permissions failure for "
          + currentDomain
          + ": "
          + getAcceptablePermissions();
    } else {
      if (permissionInfos.size() == 1) {
        return "Check permission failure for "
            + currentDomain
            + ": "
            + permissionInfos.iterator().next();
      }
      return "Check permissions failure for " + currentDomain + ": " + permissionInfos;
    }
  }

  /**
   * Gets the associated access control context information.
   *
   * @return the associated access control context information
   */
  @VisibleForTesting
  AccessControlContextInfo getContext() {
    return context;
  }

  /**
   * Gets the index in the stack for the frame that doesn't have the failed permission.
   *
   * @return the index in the stack for the frame that doesn't have the failed permission, <code>-1
   *     </code> if no failures
   */
  @VisibleForTesting
  int getFailedStackIndex() {
    return failedStackIndex;
  }

  /**
   * Gets the index in the stack of the last place (i.e. lowest index) a domain extended its
   * privileges. Everything between 0 til this index is of interest for the security manager. Frames
   * deemed to do that on behalf of their caller are ignored.
   *
   * @return the stack index of the last place a domain extended its privileges or <code>-1</code>
   *     if none found
   */
  @VisibleForTesting
  int getPrivilegedStackIndex() {
    return privilegedStackIndex;
  }

  /**
   * Gets the protection domains (i.e. bundle name/domain location) in the security context as
   * recomputed here.
   *
   * @return the list of protection domains (i.e. bundle name/domain location) in the security
   *     context as recomputed here
   */
  @VisibleForTesting
  List<String> getComputedDomains() {
    return domains;
  }

  /**
   * Gets the index in the recomputed domains list where the reported security exception is to be
   * generated for.
   *
   * @return the index for the failed domain or <code>-1</code> if no failures exist
   */
  @VisibleForTesting
  int getFailedDomainIndex() {
    return failedDomainIndex;
  }

  @VisibleForTesting
  String[] getCombinedDomains() {
    return isCombined.stream().mapToObj(domains::get).toArray(String[]::new);
  }

  /**
   * Checks if the specified domain index corresponds to a combined domain which means it cannot be
   * analyzed based on its stack location.
   *
   * @param index the index of the domain to check
   * @return <code>true</code> if the specified domain is considered to have been combined; <code>
   *     false</code> otherwise
   */
  private boolean isCombined(int index) {
    return isCombined.get(index);
  }

  /**
   * Checks if the specified domain corresponds to a combined domain which means it cannot be
   * analyzed based on its stack location.
   *
   * @param domain the domain to check
   * @return <code>true</code> if the specified domain is considered to have been combined or is not
   *     defined in the current context; <code>false</code> otherwise
   */
  private boolean isCombined(@Nullable String domain) {
    final int index = domains.indexOf(domain);

    return (index == -1) || isCombined.get(index);
  }

  /**
   * This method reproduces what the {@link
   * java.security.AccessControlContext#checkPermission(Permission)} does whenever it checks for
   * permissions. It goes through the stack and builds a list of domains based on each stack frame
   * encountered. If the domain is already known it moves on. if it encounters the doPrivileged()
   * block, it stops processing the stack. As it goes through it, it checks if the corresponding
   * domain implies() the permission it currently checks and if not, it would normally generate the
   * exception.
   *
   * <p>By re-implementing this logic, we can now see what would happen if we change permissions or
   * if we extend privileges at a specific location in our code. It actually allows us to verify if
   * there would be a line later that would create another problem.
   *
   * <p>When the breakpoint is invoked, we could extract that information from the loop in the
   * <code>AccessControlContext.checkPermission()</code> method. But instead of doing that, it is
   * simpler to keep the same logic to recompute.
   *
   * <p>We shall also check the stack and the failed permission against all acceptable patterns and
   * if one matches, we will skip mark it as acceptable.
   *
   * @return <code>true</code> if all granted domains were required; <code>false</code> if we didn't
   *     need all of them which would mean this is an invalid option as we are granting more than we
   *     need
   */
  private boolean recompute() {
    domains.clear();
    isCombined.clear();
    this.failedStackIndex = -1;
    this.failedDomainIndex = -1;
    computeDoPrivilegedIndexes();
    final boolean isSolution = !grantedDomains.isEmpty() || !doPrivileged.isEmpty();
    final Set<String> grantedDomains = new HashSet<>(super.grantedDomains);
    String failedDomain = recomputeFromStack(grantedDomains);

    if (!isSolution) { // only correlate if this is representing the failure and not a solution
      correlateStackDomains();
    }
    failedDomain = recomputeFromContext(grantedDomains, failedDomain);
    // we are assuming here that the boot domain can never indicate a failure as it should have all
    // permissions
    this.failedDomainIndex = (failedDomain != null) ? domains.indexOf(failedDomain) : -1;
    return grantedDomains.isEmpty();
  }

  /**
   * Check the stack for the first doPrivileged() block and check if that is done on behalf of its
   * caller and keep track of it such that we can identify its corresponding domain later as not
   * being a combined one even though the context would potentially report it as such. We do this as
   * we want to still analyze the corresponding stack line using a doPrivilegedBlock() which we
   * won't do for non-combined domains.
   */
  private void computeDoPrivilegedIndexes() {
    this.privilegedStackIndex = -1;
    for (int i = 0; i < stack.size(); i++) {
      final StackFrameInformation frame = stack.get(i);

      // note: there cannot be a call to doPrivileged() without another frame following that
      // as such, doing a blind (i+1) is safe and will never exceed stack.size()
      if (frame.isDoPrivilegedBlock()) {
        // found a stack break that we care about, we have to stop after including the next frame
        // as part of the stack analysis since it is the one calling doPrivileged()
        //
        // then we checked if the frame following the call to doPrivileged() is calling it on behalf
        // of its own caller. this is a special case to handle situations like
        // javax.security.auth.Subject:422
        // we therefore ignore that break since we want to account for its callers as part of the
        // stack
        // note: there cannot be a call to one those special cases without another frame following
        // that as such, doing a blind (i+1 or i+2) is safe and will never exceed stack.size()
        final StackFrameInformation nextFrame = stack.get(i + 1);

        if (nextFrame.isCallingDoPrivilegedBlockOnBehalfOfCaller()) {
          this.privilegedStackIndex = i + 2;
          // we want to preserve the set of domains we imply to come from the stack and not be
          // combined when we are analyzing a solution
          if (onBehalfOfCallerPrivilegedDomains.isEmpty()) {
            onBehalfOfCallerPrivilegedDomains.add(frame.getDomain());
            onBehalfOfCallerPrivilegedDomains.add(nextFrame.getDomain());
            onBehalfOfCallerPrivilegedDomains.add(stack.get(i + 2).getDomain());
          }
        } else if (privilegedStackIndex == -1) {
          this.privilegedStackIndex = i + 1;
        }
        break;
      }
    }
  }

  @Nullable
  private String recomputeFromContext(Set<String> grantedDomains, @Nullable String failedDomain) {
    // at this point, we already validated all stack entries, so we should be good to just copy
    // the context domains here and bring in all combined domains and filter out any stack entries
    // not in our computed set since those would have been skipped by the fact that we are extending
    // privileges
    final List<String> contextDomains = context.getDomains();
    final List<String> stackDomains = new ArrayList<>(domains);
    int j = 0;

    domains.clear();
    isCombined.clear();
    for (int i = 0; i < contextDomains.size(); i++) {
      final String domain = contextDomains.get(i);

      if (!domains.contains(domain)) {
        final boolean isACombinedDomain = context.isCombined(i);
        final boolean isPartOfOnBehalfOfCallerPrivilegedDomains =
            onBehalfOfCallerPrivilegedDomains.contains(domain);

        // if we didn't compute this domain as a stack domain and it is not combined then this stack
        // domain must have been skipped in our calculations because of an artificial doPrivileged()
        // block so ignore it otherwise check if it is a domain implied to be on the stack as they
        // were part of a call to doPrivileged() on behalf of its caller since it should be reported
        // by our stack computation and not as a combined one
        if (!stackDomains.contains(domain)
            && (!isACombinedDomain || isPartOfOnBehalfOfCallerPrivilegedDomains)) {
          continue;
        }
        failedDomain = processContextDomain(grantedDomains, domain, failedDomain);
        // although it might be marked combined in the context, it is possible that we detected
        // while analyzing the stack that a doPrivileged() block was done on behalf of a caller, in
        // such case we want to mark the domain following that stack break as not combined such that
        // we will still allow us to analyze the corresponding stack line for doPrivileged() block
        // solution
        if (isACombinedDomain && !isPartOfOnBehalfOfCallerPrivilegedDomains) {
          isCombined.set(j);
        }
        j++;
      }
    }
    return failedDomain;
  }

  @Nullable
  private String processContextDomain(
      Set<String> grantedDomains, @Nullable String domain, @Nullable String failedDomain) {
    domains.add(domain);
    if (failedDomain == null) {
      if (!context.isPrivileged(domain)) { // found the place it will fail!!!!
        return domain;
      } else {
        // keep track of the fact that this granted domain helped if it was one
        // that we artificially granted the permission to
        grantedDomains.remove(domain);
      }
    }
    return failedDomain;
  }

  private void recomputeAcceptablePattern(
      List<Pattern> stackPatterns, StackFrameInformation frame, int index) {
    if (!isAcceptable()) {
      final String location = frame.getLocation();

      this.acceptablePattern =
          stackPatterns
              .stream()
              .filter(p -> p.matchLocations(index, location))
              .filter(Pattern::wasAllMatched)
              .findFirst()
              .orElse(null);
    }
  }

  @Nullable
  private String recomputeFromStack(Set<String> grantedDomains) {
    final List<Pattern> stackPatterns =
        SecurityCheckInformation.ACCEPTABLE_PATTERNS
            .stream()
            .filter(p -> p.matchAllPermissions(permissionInfos))
            .map(Pattern::new)
            .collect(Collectors.toList());
    String failedDomain = null;
    // +1 on the privilegedStackIndex is to ensure we loop through privilegedStackIndex below
    final int last = (privilegedStackIndex != -1) ? (privilegedStackIndex + 1) : stack.size();

    for (int i = 0; i < last; i++) {
      final StackFrameInformation frame = stack.get(i);

      recomputeAcceptablePattern(stackPatterns, frame, i);
      final String domain = frame.getDomain();

      if (!domains.contains(domain)) {
        domains.add(domain);
      }
      if (failedDomain == null) {
        if (!frame.isPrivileged(context.getPrivilegedDomains())) { // found where it failed!
          failedDomain = domain;
          this.failedStackIndex = i;
        } else {
          // keep track of the fact that this granted domain helped if it was one
          // that we artificially granted the permission to
          grantedDomains.remove(domain);
        }
      }
    }
    return failedDomain;
  }

  private void correlateStackDomains() {
    // each domain we computed here should also be present in the context's domains
    final String bootDomain =
        debug.isOSGi() ? StackFrameInformation.BUNDLE0 : StackFrameInformation.BOOT_DOMAIN;
    final List<String> contextDomains = context.getDomains();

    for (int i = 0; i < domains.size(); i++) {
      final String domain = domains.get(i);
      final int index = contextDomains.indexOf(domain);

      // for some reasons the AccessController doesn't always include the boot domain as part of
      // its stack context even though by design, our breakpoint is inside that class
      // since when we calculate the stack we see that domain, this would cause a failure here
      // so let's skip it
      if ((index == -1) && (domain != null)) {
        dumpTroubleshootingInfo(
            "AN ERROR OCCURRED WHILE ATTEMPTING TO ANALYZE THE SECURITY EXCEPTION,",
            "A DOMAIN WE COMPUTED FROM THE STACK (INDEX: " + i + ") CANNOT BE FOUND IN THE",
            "CURRENT ACCESS CONTROL CONTEXT");
        throw new InternalError(
            "unable to find a domain computed from the stack in the access control context: "
                + Objects.toString(domain, bootDomain));
      }
    }
    // each stack domains defined in the context should be accounted for here
    for (int i = 0; i < contextDomains.size(); i++) {
      final String domain = contextDomains.get(i);

      if (!context.isCombined(i) && !domains.contains(domain)) {
        dumpTroubleshootingInfo(
            "AN ERROR OCCURRED WHILE ATTEMPTING TO ANALYZE THE SECURITY EXCEPTION,",
            "A DOMAIN IN THE CURRENT ACCESS CONTROL CONTEXT (INDEX: " + i + ") CANNOT",
            "BE CORRELATED TO ONE COMPUTED FROM THE STACK");
        throw new InternalError(
            "unable to correlate a domain in the access control context with those computed from the stack: "
                + Objects.toString(domain, bootDomain));
      }
    }
  }

  private List<SecuritySolution> analyze0() {
    List<SecuritySolution> solutions = analysis;

    if (solutions == null) {
      if (invalid) { // if this is not a valid solution then the analysis should be empty
        solutions = Collections.emptyList();
        this.analysis = solutions;
      } else if (((failedStackIndex == -1) && (failedDomainIndex == -1)) || isAcceptable()) {
        // no issues here (i.e. good solution) or acceptable security exception so return self
        solutions = Collections.singletonList(this);
        this.analysis = Collections.emptyList();
      } else {
        solutions = new ArrayList<>();
        // first see what happens if we grant the missing permission to the failed domain
        solutions.addAll(new SecurityCheckInformation(this).analyze0());
        if (debug.canDoPrivilegedBlocks()) {
          analyzeDoPrivilegedBlocks(solutions);
        }
        Collections.sort(solutions); // sort the result
        this.analysis = solutions;
      }
    }
    return solutions;
  }

  private void analyzeDoPrivilegedBlocks(List<SecuritySolution> solutions) {
    // now check if we could extend the privileges of a domain that comes up
    // before which already has the permission and which was not marked combined
    for (int i = failedStackIndex - 1; i >= 0; i--) {
      final StackFrameInformation frame = stack.get(i);
      final String domain = frame.getDomain();

      if (frame.isPrivileged(context.getPrivilegedDomains())
          && frame.canDoPrivilegedBlocks(debug)
          && !isCombined(domain)) {
        solutions.addAll(new SecurityCheckInformation(this, i).analyze0());
      }
    }
  }

  @SuppressWarnings("squid:S106" /* this is a console application */)
  private void dumpPermission() {
    if (isAcceptable()) {
      System.out.println(ACDebugger.PREFIX + "Acceptable permissions:");
      System.out.println(ACDebugger.PREFIX + "    " + getAcceptablePermissions());
    } else {
      final String s = (permissionInfos.size() == 1) ? "" : "s";

      System.out.println(ACDebugger.PREFIX + "Permission" + s + ":");
      permissionInfos.forEach(p -> System.out.println(ACDebugger.PREFIX + "    " + p));
    }
  }

  @SuppressWarnings("squid:S106" /* this is a console application */)
  private void dumpHowToFix(boolean osgi) {
    if (!grantedDomains.isEmpty()) {
      final String ds = (grantedDomains.size() == 1) ? "" : "s";
      final String ps = (permissionInfos.size() == 1) ? "" : "s";

      System.out.println(
          ACDebugger.PREFIX
              + "Granting permission"
              + ps
              + " to "
              + (osgi ? "bundle" : "domain")
              + ds
              + ":");
      grantedDomains.forEach(d -> System.out.println(ACDebugger.PREFIX + "    " + d));
    }
    if (!doPrivileged.isEmpty()) {
      System.out.println(ACDebugger.PREFIX + "Extending privileges at:");
      doPrivileged.forEach(f -> System.out.println(ACDebugger.PREFIX + "    " + f));
    }
  }

  @SuppressWarnings("squid:S106" /* this is a console application */)
  private void dumpContext(boolean osgi) {
    final String bootDomain =
        debug.isOSGi() ? StackFrameInformation.BUNDLE0 : StackFrameInformation.BOOT_DOMAIN;

    System.out.println(ACDebugger.PREFIX + "Context:");
    for (int i = 0; i < domains.size(); i++) {
      final String domain = domains.get(i);

      System.out.println(
          ACDebugger.PREFIX
              + " "
              + ((i == failedDomainIndex) ? "--> " : "    ")
              + (context.isPrivileged(domain) ? "" : "*")
              + Objects.toString(domain, bootDomain)
              + (isCombined(i) ? " (combined)" : ""));
    }
  }

  @SuppressWarnings("squid:S106" /* this is a console application */)
  private void dumpStack(boolean osgi) {
    System.out.println(ACDebugger.PREFIX + "Stack:");
    final int size = stack.size();

    for (int i = 0; i < size; i++) {
      System.out.println(
          ACDebugger.PREFIX
              + " "
              + ((i == failedStackIndex) ? "-->" : "   ")
              + " at "
              + (isAcceptable() && acceptablePattern.wasMatched(i) ? "#" : "")
              + stack.get(i).toString(osgi, context.getPrivilegedDomains()));
      if ((privilegedStackIndex != -1) && (i == privilegedStackIndex)) {
        System.out.println(
            ACDebugger.PREFIX + "    ----------------------------------------------------------");
      }
    }
  }

  private void dump0(boolean osgi) {
    dumpPermission();
    dumpHowToFix(osgi);
    dumpContext(osgi);
    dumpStack(osgi);
  }

  @SuppressWarnings("squid:S106" /* this is a console application */)
  private void dumpTroubleshootingInfo(String... msg) {
    final String bootDomain =
        debug.isOSGi() ? StackFrameInformation.BUNDLE0 : StackFrameInformation.BOOT_DOMAIN;

    System.err.println(ACDebugger.PREFIX);
    System.err.println(ACDebugger.PREFIX + SecurityCheckInformation.DOUBLE_LINES);
    Stream.of(msg).map(ACDebugger.PREFIX::concat).forEach(System.err::println);
    System.err.println(
        ACDebugger.PREFIX
            + "PLEASE REPORT AN ISSUE WITH THE FOLLOWING INFORMATION AND INSTRUCTIONS");
    System.err.println(ACDebugger.PREFIX + "ON HOW TO REPRODUCE IT");
    System.err.println(ACDebugger.PREFIX + SecurityCheckInformation.DOUBLE_LINES);
    System.err.println(
        ACDebugger.PREFIX + "PERMISSION" + ((permissionInfos.size() == 1) ? ":" : "S:"));
    permissionInfos.forEach(p -> System.err.println(ACDebugger.PREFIX + "    " + p));
    if (isAcceptable()) {
      System.err.println(ACDebugger.PREFIX + "ACCEPTABLE PERMISSIONS: ");
      System.err.println(ACDebugger.PREFIX + "    " + getAcceptablePermissions());
    }
    context.dumpTroubleshootingInfo();
    System.err.println(ACDebugger.PREFIX + "COMPUTED CONTEXT:");
    for (int i = 0; i < domains.size(); i++) {
      final String domain = domains.get(i);

      System.err.println(
          ACDebugger.PREFIX
              + "  "
              + (context.isPrivileged(domain) ? "" : "*")
              + Objects.toString(domain, bootDomain)
              + (isCombined(i) ? " (combined)" : ""));
    }
    System.err.println(ACDebugger.PREFIX + "STACK:");
    final int size = stack.size();

    for (int i = 0; i < size; i++) {
      System.err.println(
          ACDebugger.PREFIX
              + "  at "
              + stack.get(i).toString(debug.isOSGi(), context.getPrivilegedDomains()));
      if ((privilegedStackIndex != -1) && (i == privilegedStackIndex)) {
        System.err.println(
            ACDebugger.PREFIX + "    ----------------------------------------------------------");
      }
    }
    System.err.println(ACDebugger.PREFIX + SecurityCheckInformation.DOUBLE_LINES);
  }

  /** Pattern class for matching specific permission and stack information. */
  private static class Pattern {
    private final java.util.regex.Pattern permissionPattern;
    private final List<java.util.regex.Pattern> stackPatterns;
    private final List<Integer> stackIndexes;

    private Pattern(String permissionPattern) {
      this.permissionPattern = java.util.regex.Pattern.compile(permissionPattern);
      this.stackPatterns = new ArrayList<>(8);
      this.stackIndexes = null;
    }

    public Pattern(Pattern pattern) {
      this.permissionPattern = pattern.permissionPattern;
      this.stackPatterns = new ArrayList<>(pattern.stackPatterns);
      this.stackIndexes = new ArrayList<>(stackPatterns.size());
    }

    private void addStack(String stackPattern) {
      stackPatterns.add(java.util.regex.Pattern.compile(stackPattern));
    }

    @SuppressWarnings("squid:S00112" /* Forced to by the Java debugger API */)
    private void validate() {
      if (stackPatterns.isEmpty()) {
        throw new Error(
            "missing stack frame information for [" + permissionPattern.pattern() + "]");
      }
    }

    public String getPermissionInfos() {
      return permissionPattern.pattern();
    }

    public boolean matchAllPermissions(Set<String> permissionInfos) {
      return permissionInfos.stream().map(permissionPattern::matcher).allMatch(Matcher::matches);
    }

    public boolean matchLocations(int index, String location) {
      if (!stackPatterns.isEmpty() && stackPatterns.get(0).matcher(location).matches()) {
        stackPatterns.remove(0);
        stackIndexes.add(index);
        return true;
      }
      return false;
    }

    public boolean wasAllMatched() {
      return stackPatterns.isEmpty();
    }

    public boolean wasMatched(int index) {
      return stackIndexes.contains(index);
    }
  }

  /** Line processors for returning a list of patterns while trimming and ignoring comment lines. */
  private static class PatternProcessor implements LineProcessor<List<Pattern>> {
    private final List<Pattern> result = new ArrayList<>();
    private Pattern current = null;

    @Override
    public boolean processLine(String line) throws IOException {
      final String trimmed = line.trim();

      if (trimmed.startsWith("#")) { // nothing to do, just skip that line and continues
      } else if (trimmed.isEmpty()) {
        if (current != null) {
          current.validate();
          this.current = null;
        }
      } else if (current == null) {
        this.current = new Pattern(trimmed);
        result.add(current);
      } else {
        current.addStack(trimmed);
      }
      return true;
    }

    @Override
    public List<Pattern> getResult() {
      if (current != null) {
        current.validate();
        this.current = null;
      }
      return Collections.unmodifiableList(result);
    }
  }
}

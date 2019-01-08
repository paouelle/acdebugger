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

// NOSONAR - squid:S1191 - Using the Java debugger API

import com.google.common.annotations.VisibleForTesting;
import com.sun.jdi.ArrayReference; // NOSONAR
import com.sun.jdi.ClassType; // NOSONAR
import com.sun.jdi.Method; // NOSONAR
import com.sun.jdi.ObjectReference; // NOSONAR
import com.sun.jdi.Type; // NOSONAR
import java.security.AccessController;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;
import javax.annotation.Nullable;
import org.codice.acdebugger.ACDebugger;
import org.codice.acdebugger.api.Debug;
import org.codice.acdebugger.api.LocationUtil;
import org.codice.acdebugger.api.PermissionUtil;
import org.codice.acdebugger.api.ReflectionUtil;
import org.codice.acdebugger.api.StackFrameInformation;

/** Class used to hold access control context information */
public class AccessControlContextInfo {
  private static volatile ClassType accessControllerClass = null;

  private static volatile Method getStackAccessControlContextMethod = null;

  /** The associated debug session. */
  private final Debug debug;

  private final ObjectReference acc;
  private final ObjectReference permission;
  private final Set<String> permissionInfos;
  private final Type combiner;

  /** list of protection domains (i.e. bundle name/domain location) in the context */
  private final List<ObjectReference> domainReferences;

  /**
   * list of protection domains (i.e. bundle name/domain location) in the context. It can have nulls
   * and duplicates.
   */
  private final List<String> domains;

  /**
   * list of protection domains in the stack as reported by {@link
   * AccessController#getStackAccessControlContext()}
   */
  private final List<ObjectReference> stackDomainReferences;

  /**
   * list of protection domains in the stack (i.e. bundle name/domain location) in the context. It
   * can have nulls and duplicates.
   */
  private final List<String> stackDomains;

  /**
   * bit set indicating if an entry in the domains list was combined. An entry that came from the
   * stack could potentially be surrounded by a <code>doPrivileged()</code> block and be correlated
   * with the stack information retrieved from the current thread.
   */
  private final BitSet isCombined;

  /**
   * The index of the first domain in the list of domains that is reporting not being granted the
   * permission.
   */
  private final int currentDomainIndex;

  /** Domain where the exception is being reported. */
  private final ObjectReference currentDomainReference;

  /**
   * Domain location/bundle name where the exception is being reported or <code>null</code> if
   * unable to determine the domain location or bundle name.
   */
  @Nullable private final String currentDomain;

  /* list of protection domains (i.e. bundle name/domain location) that are granted the failed permissions */
  private final Set<String> privilegedDomains;

  /**
   * Creates a new access control context information.
   *
   * @param debug the current debug session
   * @param acc the access control context object
   * @param currentDomainIndex the index of the first domain (a.k.a. the current domain) in the
   *     above list that reported not being granted the specified permission
   * @param permission the permission being checked
   */
  public AccessControlContextInfo(
      Debug debug, ObjectReference acc, int currentDomainIndex, ObjectReference permission) {
    final ReflectionUtil reflection = debug.reflection();

    AccessControlContextInfo.init(reflection);
    this.debug = debug;
    final PermissionUtil permissions = debug.permissions();
    final ArrayReference context =
        reflection.get(acc, "context", "[Ljava/security/ProtectionDomain;");
    final ObjectReference stackAcc =
        AccessControlContextInfo.getStackAccessControlContext(reflection);
    final ArrayReference stackContext =
        reflection.get(stackAcc, "context", "[Ljava/security/ProtectionDomain;");

    this.acc = acc;
    final ObjectReference combinerReference =
        reflection.get(acc, "combiner", "Ljava/security/DomainCombiner;");

    this.combiner = (combinerReference != null) ? combinerReference.type() : null;
    this.permission = permission;
    this.permissionInfos = permissions.getPermissionStrings(permission);
    this.currentDomainIndex = currentDomainIndex;
    // domains in contexts can only be object references
    this.domainReferences = (List<ObjectReference>) (List) context.getValues();
    this.stackDomainReferences = (List<ObjectReference>) (List) stackContext.getValues();
    this.domains = new ArrayList<>(domainReferences.size());
    this.stackDomains = new ArrayList<>(stackDomainReferences.size());
    this.isCombined = new BitSet(domainReferences.size());
    this.privilegedDomains = new HashSet<>(domainReferences.size() * 3 / 2);
    privilegedDomains.add(null); // boot domain/bundle-0 always have permissions
    computeInfo(debug.locations(), permissions, reflection);
    this.currentDomainReference = domainReferences.get(currentDomainIndex);
    this.currentDomain = domains.get(currentDomainIndex);
  }

  @VisibleForTesting
  @SuppressWarnings("squid:S00107" /* Used for testing */)
  AccessControlContextInfo(
      Debug debug,
      ObjectReference acc,
      Type combiner,
      List<ObjectReference> domainReferences,
      List<String> domains,
      List<ObjectReference> stackDomainReferences,
      List<String> stackDomains,
      BitSet isCombined,
      int currentDomainIndex,
      ObjectReference permission,
      Set<String> permissionInfos,
      Set<String> privilegedDomains) {
    this.debug = debug;
    this.acc = acc;
    this.combiner = combiner;
    this.permission = permission;
    this.permissionInfos = permissionInfos;
    this.currentDomainIndex = currentDomainIndex;
    this.domainReferences = domainReferences;
    this.domains = domains;
    this.stackDomainReferences = stackDomainReferences;
    this.stackDomains = stackDomains;
    this.isCombined = isCombined;
    this.currentDomainReference = domainReferences.get(currentDomainIndex);
    this.currentDomain = domains.get(currentDomainIndex);
    this.privilegedDomains = privilegedDomains;
  }

  /**
   * Creates a new access control context information from another one corresponding to a scenario
   * where the specified domain would have been granted the permission.
   *
   * @param info the access control context information being cloned
   * @param domain the domain that would have been granted the permission
   * @return a corresponding context info
   */
  private AccessControlContextInfo(AccessControlContextInfo info, String domain) {
    this(
        info.debug,
        info.acc,
        info.combiner,
        info.domainReferences,
        info.domains,
        info.stackDomainReferences,
        info.stackDomains,
        info.isCombined,
        info.currentDomainIndex,
        info.permission,
        info.permissionInfos,
        // add the specified domain as a privileged one
        AccessControlContextInfo.copyAndAdd(info.privilegedDomains, domain));
  }

  /**
   * Gets the permissions associated with this access control context information.
   *
   * @return the permissions associated with this context info
   */
  public Set<String> getPermissions() {
    return permissionInfos;
  }

  /**
   * Gets the list of protection domains (i.e. bundle name/domain location) in the context.
   *
   * @return the list of protection domains (i.e. bundle name/domain location) in the context
   */
  public List<String> getDomains() {
    return domains;
  }

  /**
   * Gets the domain location/bundle name where the exception is being reported.
   *
   * @return the domain location/bundle name where the exception is being reported or <code>null
   *     </code> if unable to determine the domain location or bundle name
   */
  @Nullable
  public String getCurrentDomain() {
    return currentDomain;
  }

  /**
   * Gets the reference to the domain where the exception is being reported.
   *
   * @return the domain reference where the exception is being reported
   */
  public ObjectReference getCurrentDomainReference() {
    return currentDomainReference;
  }

  /**
   * Gets the index of the first domain in the list of domains that is reporting not being granted
   * the permission.
   *
   * @return the index of the first domain in the list of domains that is reporting not being
   *     granted the permission
   */
  public int getCurrentDomainIndex() {
    return currentDomainIndex;
  }

  /**
   * Checks if the specified domain index corresponds to a combined domain which means it cannot be
   * analyzed based on its stack location.
   *
   * @param index the index of the domain to check
   * @return <code>true</code> if the specified domain is considered to have been combined; <code>
   *     false</code> otherwise
   */
  public boolean isCombined(int index) {
    return isCombined.get(index);
  }

  /**
   * Checks if the specified domain is privileged.
   *
   * @param domain the domain to check
   * @return <code>true</code> if the specified domain is granted the permission; <code>false</code>
   *     otherwise
   */
  public boolean isPrivileged(@Nullable String domain) {
    return privilegedDomains.contains(domain);
  }

  /**
   * Gets the set of privileged domains.
   *
   * @return the set of domains which are granted the permission
   */
  public Set<String> getPrivilegedDomains() {
    return privilegedDomains;
  }

  /**
   * Creates a new access control context information corresponding corresponding to a scenario
   * where the specified domain would have been granted the permission.
   *
   * @param domain the domain that would have been granted the permission
   * @return a corresponding context info
   */
  public AccessControlContextInfo grant(String domain) {
    return new AccessControlContextInfo(this, domain);
  }

  @SuppressWarnings("squid:S106" /* this is a console application */)
  void dumpTroubleshootingInfo(String... msg) {
    System.err.println(ACDebugger.PREFIX);
    System.err.println(ACDebugger.PREFIX + SecurityCheckInformation.DOUBLE_LINES);
    Stream.of(msg).map(ACDebugger.PREFIX::concat).forEach(System.err::println);
    System.err.println(
        ACDebugger.PREFIX
            + "PLEASE REPORT AN ISSUE WITH THE FOLLOWING INFORMATION AND INSTRUCTIONS");
    System.err.println(ACDebugger.PREFIX + "ON HOW TO REPRODUCE IT");
    System.err.println(ACDebugger.PREFIX + SecurityCheckInformation.DOUBLE_LINES);
    dumpTroubleshootingInfo();
  }

  @SuppressWarnings("squid:S106" /* this is a console application */)
  void dumpTroubleshootingInfo() {
    final ReflectionUtil reflection = debug.reflection();

    System.err.println(ACDebugger.PREFIX + "LOCAL 'i' VARIABLE: " + currentDomainIndex);
    System.err.println(
        ACDebugger.PREFIX
            + "CURRENT DOMAIN: "
            + currentDomain
            + " <"
            + currentDomainReference
            + '>');
    System.err.println(ACDebugger.PREFIX + "ACCESS CONTROL CONTEXT: <" + acc + '>');
    System.err.println(ACDebugger.PREFIX + "  -- combiner: " + combiner);
    System.err.println(
        ACDebugger.PREFIX
            + "  -- privileged context: "
            + reflection.get(acc, "privilegedContext", "Ljava/security/AccessControlContext;"));
    System.err.println(
        ACDebugger.PREFIX
            + "  -- parent context: "
            + reflection.get(acc, "parent", "Ljava/security/AccessControlContext;"));
    System.err.println(
        ACDebugger.PREFIX + "  -- isPrivileged: " + reflection.get(acc, "isPrivileged", "Z"));
    System.err.println(
        ACDebugger.PREFIX + "  -- isAuthorized: " + reflection.get(acc, "isAuthorized", "Z"));
    System.err.println(
        ACDebugger.PREFIX + "  -- isWrapped: " + reflection.get(acc, "isWrapped", "Z"));
    System.err.println(
        ACDebugger.PREFIX + "  -- isLimited: " + reflection.get(acc, "isLimited", "Z"));
    dumpDomains(domainReferences, domains, isCombined);
    System.err.println(ACDebugger.PREFIX + "STACK ACCESS CONTROL CONTEXT:");
    dumpDomains(stackDomainReferences, stackDomains, new BitSet());
  }

  @SuppressWarnings("squid:S106" /* this is a console application */)
  private void dumpDomains(
      List<ObjectReference> domainReferences, List<String> domains, BitSet isCombined) {
    final String bootDomain =
        debug.isOSGi() ? StackFrameInformation.BUNDLE0 : StackFrameInformation.BOOT_DOMAIN;

    for (int i = 0; i < domains.size(); i++) {
      final ObjectReference domainReference = domainReferences.get(i);
      final String domain = domains.get(i);
      final boolean privileged = isPrivileged(domain);

      System.err.println(
          ACDebugger.PREFIX
              + "  "
              + (privileged ? "" : "*")
              + Objects.toString(domain, bootDomain)
              + (isCombined.get(i) ? " (combined) <" : " <")
              + domainReference
              + '>');
    }
  }

  private void computeInfo(
      LocationUtil locations, PermissionUtil permissions, ReflectionUtil reflection) {
    computeStackDomainInfo(locations, permissions);
    computeDomainInfo(locations, permissions);
    computeIsCombined(reflection);
  }

  private void computeIsCombined(ReflectionUtil reflection) {
    if (reflection.isAssignableFrom("Ljavax/security/auth/SubjectDomainCombiner;", combiner)) {
      // this combiner is known to add new entries only after the stack
      computeIsCombinedAfterStack();
    } else if (combiner == null) { // inherited entries are all added before the stack
      computeIsCombinedBeforeStack();
    } else { // we can't really tell - so mark all entries combined
      dumpTroubleshootingInfo("AN UNKNOWN COMBINER WAS JUST DISCOVERED: " + combiner);
      isCombined.set(0, domainReferences.size());
    }
  }

  // in this case, we should find the stack as is and then following that new domains not already
  // defined by the stack context
  private void computeIsCombinedAfterStack() {
    for (int i = 0; i < stackDomains.size(); i++) {
      final String stackDomain = stackDomains.get(i);
      final String domain = domains.get(i);

      if (!Objects.equals(stackDomain, domain)) { // this should not happen
        final String bootDomain =
            debug.isOSGi() ? StackFrameInformation.BUNDLE0 : StackFrameInformation.BOOT_DOMAIN;

        dumpTroubleshootingInfo(
            "AN ERROR OCCURRED WHILE ATTEMPTING TO ANALYZE THE SECURITY EXCEPTION,",
            "A DOMAIN IN THE CURRENT ACCESS CONTROL CONTEXT (INDEX: " + i + ") DOES NOT",
            "MATCH THE CORRESPONDING DOMAIN IN THE ACCESS CONTROL CONTEXT STACK");
        throw new InternalError(
            "unable to correlate the access control context and the access control context stack: "
                + domain
                + " and "
                + Objects.toString(stackDomain, bootDomain));
      }
    }
    for (int i = stackDomainReferences.size(); i < domainReferences.size(); i++) {
      isCombined.set(i);
    }
  }

  // in this case, we should find part of the stack after combined domains. Part because if some
  // domains from the stack were already combined before, they will not be duplicated so there might
  // be missing stack domain entries (as long as they exist before the beginning of the stack)
  private void computeIsCombinedBeforeStack() {
    isCombined.set(0, domains.size()); // assume all combined until proven otherwise
    for (int i = 0; i < stackDomains.size(); i++) {
      final String stackDomain = stackDomains.get(i);

      if (!domains.contains(stackDomain)) { // this should not happen
        final String bootDomain =
            debug.isOSGi() ? StackFrameInformation.BUNDLE0 : StackFrameInformation.BOOT_DOMAIN;

        dumpTroubleshootingInfo(
            "AN ERROR OCCURRED WHILE ATTEMPTING TO ANALYZE THE SECURITY EXCEPTION,",
            "A DOMAIN IN THE CURRENT ACCESS CONTROL CONTEXT STACK (INDEX: " + i + ") CANNOT",
            "BE FOUND IN THE ACCESS CONTROL CONTEXT STACK");
        throw new InternalError(
            "unable to correlate the access control context stack with the access control context: "
                + Objects.toString(stackDomain, bootDomain));
      }
    }
    for (int i = 0; i < domains.size(); i++) {
      final int j = stackDomains.indexOf(domains.get(i));

      if (j != -1) {
        isCombined.clear(i);
      } else {
        // if we get here than the current domain is not from the stack which means that everything
        // before will be considered combined (event if it was also in the stack)
        isCombined.set(0, i + 1);
      }
    }
  }

  private void computeStackDomainInfo(LocationUtil locations, PermissionUtil permissions) {
    for (int i = 0; i < stackDomainReferences.size(); i++) {
      final ObjectReference domainReference = stackDomainReferences.get(i);
      String domain = locations.get(domainReference);

      if ((domain == null) && !permissions.implies(domainReference, permission)) { // check VM
        // domain is null because it is some protection domain we cannot correlate to a domain
        // location or a bundle name and we do not have permissions which means that it cannot be
        // the boot domain/bundle location which has all permissions
        // we therefore have a situation we cannot debug. The SecurityCheckInformation will
        // actually
        // report this error when it is trying to match computed domains with the ones here
        // -- change the location to an unknown one
        domain = "unknown-" + domainReference;
      }
      stackDomains.add(domain);
    }
  }

  @SuppressWarnings("squid:S1871" /* order of each "if"s is important so we cannot combine them */)
  private void computeDomainInfo(LocationUtil locations, PermissionUtil permissions) {
    for (int i = 0; i < domainReferences.size(); i++) {
      final ObjectReference domainReference = domainReferences.get(i);
      String domain = locations.get(domainReference);

      if (i == currentDomainIndex) {
        // we know we don't have privileges since we failed here so continue but only after
        // having added the current domain to the context list
        // if domain is null then the SecurityCheckInformation will actually fail debugging and
        // generated troubleshooting info as it cannot be the boot domain/bundle-0 since that one
        // should have all permissions. It has to be some protection domain we cannot correlate to
        // a domain location or a bundle name
      } else if (i < currentDomainIndex) { // we know we have privileges since we failed after `i`
        // if domain is null because it is some protection domain we cannot correlate to a domain
        // location or a bundle name, than that is still ok as we can treat it as the boot domain/
        // bundle location which has all permissions
        permissions.grant(domain, permissionInfos);
        privilegedDomains.add(domain);
      } else if ((domain != null) && permissions.implies(domain, permissionInfos)) { // check cache
        privilegedDomains.add(domain);
      } else if (permissions.implies(domainReference, permission)) { // check attached VM
        permissions.grant(domain, permissionInfos);
        privilegedDomains.add(domain);
      } else if (domain == null) {
        // domain is null because it is some protection domain we cannot correlate to a domain
        // location or a bundle name and we do not have permissions which means that it cannot be
        // the boot domain/bundle location which has all permissions
        // we therefore have a situation we cannot debug. The SecurityCheckInformation will actually
        // report this error when it is trying to match computed domains with the ones here
        // -- change the location to an unknown one
        domain = "unknown-" + domainReference;
      }
      domains.add(domain);
    }
  }

  private static void init(ReflectionUtil reflection) {
    if (AccessControlContextInfo.accessControllerClass == null) {
      final ClassType clazz = reflection.getClass("Ljava/security/AccessController;");

      AccessControlContextInfo.accessControllerClass = clazz;
      AccessControlContextInfo.getStackAccessControlContextMethod =
          reflection.findMethod(
              clazz, "getStackAccessControlContext", "()Ljava/security/AccessControlContext;");
    }
  }

  private static ObjectReference getStackAccessControlContext(ReflectionUtil reflection) {
    try {
      return reflection.invokeStatic(
          AccessControlContextInfo.accessControllerClass,
          AccessControlContextInfo.getStackAccessControlContextMethod);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static Set<String> copyAndAdd(Set<String> set, String element) {
    final Set<String> copy = new HashSet<>(set);

    copy.add(element);
    return copy;
  }
}

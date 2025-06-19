# Kubernetes Resource Refactoring Report

## 1. Overview of Current Kubernetes Resource Organization

Our Kubernetes resources are currently managed using a combination of Helm charts and Kustomize configurations.

*   **Helm Charts:** Located primarily under the `charts/` directory. Each subdirectory (e.g., `istio-mesh/`, `observability/`, `security-policies/`, `spire-integration/`, `zamaz/`) appears to represent a distinct component or application, with its resources defined within its `templates/` subdirectory.
    *   Common resource kinds observed include: `AuthorizationPolicy`, `ClusterRole`, `ClusterRoleBinding`, `ConfigMap`, `DaemonSet`, `Deployment`, `DestinationRule`, `EnvoyFilter`, `Gateway`, `Job`, `Namespace`, `NetworkPolicy`, `PeerAuthentication`, `PrometheusRule`, `Role`, `RoleBinding`, `Secret`, `Service`, `ServiceAccount`, `ServiceMonitor`, `StatefulSet`, `Telemetry`, `VirtualService`.

*   **Kustomize:** Configurations are present under `deployments/kubernetes/`. This directory uses a "base and overlays" structure.
    *   `deployments/kubernetes/base/` contains common resource definitions.
        *   Resource kinds observed include: `ConfigMap`, `Deployment`, `NetworkPolicy`, `Role`, `RoleBinding`, `Service`, `ServiceAccount`.
    *   `deployments/kubernetes/overlays/` (with `production/` and `staging/` subdirectories) contains patches to customize the base configurations for different environments.
        *   Resource kinds observed in overlays (often as patches or environment-specific additions) include: `ConfigMap` (patches), `Deployment` (patches), `HorizontalPodAutoscaler`, `PodDisruptionBudget`.

This hybrid approach, while offering flexibility, presents opportunities for streamlining and standardization.

## 2. Identified Issues

Based on the observed structure and common Kubernetes practices, the following potential issues have been identified:

*   **Redundancy and Duplication:**
    *   Several resource kinds like `ConfigMap`, `Deployment`, `NetworkPolicy`, `Role`, `RoleBinding`, `Service`, and `ServiceAccount` are defined in both Helm chart templates and Kustomize bases. This can lead to duplicated effort and makes it unclear which definition is authoritative or how they relate to each other for a given application instance.
    *   For example, the `zamaz` application has its resources defined in the `charts/zamaz/templates/` directory and also has base configurations in `deployments/kubernetes/base/`. If both are deployed for the same instance of `zamaz`, it could lead to conflicting configurations or unintended overrides.

*   **Inconsistent Configuration Sources:**
    *   Managing the same application or component through both Helm and Kustomize simultaneously (e.g., deploying a base with Kustomize and then layering a Helm chart, or vice-versa) can create a complex and hard-to-trace configuration chain.

*   **Lack of Clear Demarcation:**
    *   It's not immediately clear which tool (Helm or Kustomize) is the primary source of truth for each application or component deployed in the cluster.
    *   The scope of responsibility for each Helm chart versus the Kustomize bases/overlays could be better defined. For instance, are Helm charts for third-party applications and Kustomize for in-house applications, or is the split based on some other criteria?

*   **Potential for Configuration Drift:**
    *   With multiple sources of configuration, there's a higher risk of inconsistencies and configuration drift between environments or even between different declarations for the same resource.

*   **Increased Cognitive Load:**
    *   Developers and operators need to be proficient in both Helm and Kustomize and understand how they interact in this specific setup, increasing the learning curve and operational complexity.

*   **Naming and Labeling Inconsistencies:**
    *   While not explicitly analyzed in the file listing, managing resources across two distinct systems without a strict convention can easily lead to inconsistencies in naming and labeling, impacting operational tooling, monitoring, and policy enforcement.

## 3. Recommendations for Refactoring

To address the identified issues, we propose the following refactoring strategies:

### 3.1. Standardize on a Primary Configuration Management Tool (Per Application/Component)

*   **Recommendation:** For each distinct application or service, decide whether Helm *or* Kustomize will be the primary tool for managing its Kubernetes resources. Avoid managing the same deployment with both simultaneously.
*   **Example:**
    *   If `zamaz` is an in-house application, you might decide Kustomize (using the existing `deployments/kubernetes/base/zamaz-*.yaml` and overlays) is the source of truth. The Helm chart `charts/zamaz/` should then either be deprecated or repurposed (e.g., for a different variant or a higher-level composition).
    *   Alternatively, if Helm is preferred for `zamaz`, the Kustomize definitions for `zamaz` in `deployments/kubernetes/base/` should be removed, and environment configuration should be handled via Helm values files for different overlays/environments.
*   **Rationale:** Simplifies understanding, reduces duplication, and provides a single source of truth for each deployed instance.

### 3.2. Consolidate and Deduplicate Common Resources

*   **Recommendation:** Identify resources that are largely identical across multiple charts or Kustomize bases and consolidate them.
*   **Example (NetworkPolicy):**
    *   `NetworkPolicy` definitions exist in `charts/istio-mesh/templates/network-policies.yaml`, `charts/security-policies/templates/network-policies.yaml`, and `deployments/kubernetes/base/network-policy.yaml`.
    *   **Action:**
        1.  Analyze these policies for common patterns (e.g., default-deny, DNS egress, ingress from Istio).
        2.  Create a common Kustomize base (e.g., `deployments/kubernetes/base/common-network-policies/`) or a common Helm sub-chart for these shared policies.
        3.  Application-specific charts/kustomizations can then either consume these common policies or define only their unique, additional rules.
*   **Example (RBAC - ServiceAccount, Role, RoleBinding):**
    *   `ServiceAccount`, `Role`, and `RoleBinding` are defined in `charts/security-policies/templates/service-accounts.yaml`, `charts/spire-integration/templates/rbac.yaml`, `charts/zamaz/templates/serviceaccount.yaml`, and `deployments/kubernetes/base/rbac.yaml`.
    *   **Action:** Review if these roles and service accounts are genuinely unique or if a more standardized set of roles (e.g., `app-editor`, `app-viewer`) can be defined centrally and bound to application-specific ServiceAccounts in their respective namespaces.
*   **Rationale:** Reduces boilerplate, ensures consistency, and makes global changes (e.g., updating a common NetworkPolicy) easier.

### 3.3. Establish Clear Directory Structure and Scope

*   **Recommendation:** Define a clear purpose for the `charts/` and `deployments/kubernetes/` directories.
    *   **Option 1 (Tool-based split):** `charts/` for Helm-managed applications (especially third-party ones) and `deployments/kubernetes/` for Kustomize-managed applications (typically in-house).
    *   **Option 2 (Application-centric):** Each application/component gets its own top-level directory (e.g., `apps/zamaz/`, `apps/istio-mesh/`) which can then contain either Helm charts or Kustomize configurations.
*   **Recommendation:** Within Kustomize, ensure `base/` contains truly common, environment-agnostic configurations. Overlays should only contain patches and environment-specific resources.
*   **Rationale:** Improves discoverability and makes the repository easier to navigate.

### 3.4. Adopt Consistent Naming and Labeling Conventions

*   **Recommendation:** Define and enforce a consistent naming and labeling strategy for all Kubernetes resources, regardless of whether they are managed by Helm or Kustomize. This should include labels for application name, environment, component, version, and team/owner.
*   **Example Labels:**
    ```yaml
    labels:
      app.kubernetes.io/name: zamaz
      app.kubernetes.io/instance: zamaz-prod
      app.kubernetes.io/version: "1.2.3"
      app.kubernetes.io/component: api
      app.kubernetes.io/part-of: zamaz-application
      app.kubernetes.io/managed-by: helm # or kustomize
      environment: production
      team: backend-services
    ```
*   **Rationale:** Essential for effective operational management, monitoring, logging, policy enforcement, and cost tracking.

### 3.5. Leverage Kustomize for Helm Chart Customization (If Helm is Primary)

*   **Recommendation:** If Helm is chosen as the primary tool for certain applications, but you still need significant structural changes beyond what Helm values can offer, consider using Kustomize to patch Helm chart outputs. This is a common pattern: `helm template ... | kustomize build -`.
*   **Rationale:** Provides a powerful way to apply complex customizations to third-party or standardized Helm charts without needing to fork them.

## 4. Benefits of Proposed Refactorings

Implementing these recommendations will yield significant benefits:

*   **Improved Maintainability:** A clearer structure and reduced duplication will make the codebase easier to understand, modify, and maintain.
*   **Enhanced Consistency:** Standardizing on tools (per application) and conventions will lead to more consistent deployments across different applications and environments.
*   **Reduced Complexity:** Simplifying the configuration management approach will lower the cognitive load on developers and operators.
*   **Increased Reliability:** A single source of truth for configurations and reduced duplication minimize the risk of errors and inconsistencies leading to deployment failures.
*   **Better Collaboration:** Clearer structure and conventions make it easier for team members to collaborate on managing Kubernetes resources.
*   **Streamlined Onboarding:** New team members will be ableto grasp the deployment strategies more quickly.
*   **Foundation for Automation:** A well-structured and consistent configuration codebase is easier to automate and manage with CI/CD pipelines and GitOps workflows.

By investing in this refactoring effort, we can create a more robust, scalable, and manageable Kubernetes configuration system.

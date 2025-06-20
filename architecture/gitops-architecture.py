from diagrams import Diagram, Cluster
from diagrams.k8s.compute import Deploy, Pod, ReplicaSet
from diagrams.k8s.network import Ing, SVC
from diagrams.k8s.storage import PV, PVC
from diagrams.onprem.monitoring import Prometheus, Grafana
from diagrams.onprem.vcs import Github
from diagrams.onprem.cd import ArgoCD
from diagrams.onprem.security import Vault

with Diagram("Zamaz GitOps Architecture", show=False):
    # Source Control and CI/CD
    with Cluster("CI/CD"):
        github = Github("GitHub")
        argocd = ArgoCD("ArgoCD")
        github >> argocd

    # Monitoring Stack
    with Cluster("Monitoring"):
        prometheus = Prometheus("Prometheus")
        grafana = Grafana("Grafana")
        prometheus >> grafana

    # Main Application
    with Cluster("Application - Production"):
        ing = Ing("Ingress")
        svc = SVC("Service")

        with Cluster("Canary Deployment"):
            deploy = Deploy("Rollout")
            pods = [Pod("Pod") for _ in range(3)]
            deploy >> pods

        ing >> svc >> pods
        prometheus << pods

    # Security
    with Cluster("Security"):
        vault = Vault("HashiCorp Vault")
        vault << pods

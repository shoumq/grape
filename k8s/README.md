# Kubernetes manifests

## Prereqs
- Build and push the app image somewhere reachable by your cluster.
- Replace `IMAGE_HERE` in `app.yaml` or set it via `kubectl` (see below).

## Apply base resources

```sh
kubectl apply -f k8s/db.yaml
kubectl apply -f k8s/app.yaml
```

## Load migrations into a ConfigMap

```sh
kubectl create configmap grape-migrations --from-file=migrations/001_init.sql
```

## Run migrations (Job)

```sh
kubectl apply -f k8s/migrate-job.yaml
kubectl logs job/grape-migrate
```

## Access the service

By default it creates a ClusterIP service on port 8081.
Use port-forward for local access:

```sh
kubectl port-forward svc/grape-app 8081:8081
```

## Updating the app image

```sh
kubectl set image deployment/grape-app app=IMAGE_HERE
```

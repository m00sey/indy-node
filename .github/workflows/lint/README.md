## Indy Node build container
This Docker container replaces the `code-validation.dockerfile` and is used by the GHA workflow for the lint job in Indy Node.

## Managing this container

```
docker build .
```

```
docker tag VERSION NAMESPACE/indy-node-build:TAG_NAME
```

```
docker push NAMESPACE/indy-node-build:TAG_NAME
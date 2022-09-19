To deployment,

First, copy `interweave` binary into `challenge` directory.
Then, run
```
docker-compose build
docker stack deploy -c compose.yaml
```


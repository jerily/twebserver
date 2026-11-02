From the repository root on Linux (the image builds the checked-out twebserver
2.0.0 sources and installs tpathexp 1.1.0):
```
docker build -f docker/Dockerfile . -t twebserver:latest
docker run --network host twebserver:latest
```
